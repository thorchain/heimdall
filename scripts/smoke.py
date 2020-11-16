import argparse
import time
import logging
import os
import sys
import json

from tenacity import retry, stop_after_delay, wait_fixed

from utils.segwit_addr import decode_address
from chains.binance import Binance, MockBinance
from chains.bitcoin import Bitcoin, MockBitcoin
from chains.ethereum import Ethereum, MockEthereum
from chains.thorchain import Thorchain, MockThorchain
from thorchain.thorchain import ThorchainState, ThorchainClient
from scripts.health import Health
from utils.common import Transaction, Coin, Asset, get_rune_asset
from chains.aliases import aliases_bnb, get_alias

# Init logging
logging.basicConfig(
    format="%(asctime)s | %(levelname).4s | %(message)s",
    level=os.environ.get("LOGLEVEL", "INFO"),
)

RUNE = get_rune_asset()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binance", default="http://localhost:26660", help="Mock binance server",
    )
    parser.add_argument(
        "--bitcoin",
        default="http://thorchain:password@localhost:18443",
        help="Regtest bitcoin server",
    )
    parser.add_argument(
        "--ethereum", default="http://localhost:8545", help="Localnet ethereum server",
    )
    parser.add_argument(
        "--thorchain", default="http://localhost:1317", help="Thorchain API url"
    )
    parser.add_argument(
        "--midgard", default="http://localhost:8080", help="Midgard API url"
    )
    parser.add_argument(
        "--generate-balances", default=False, type=bool, help="Generate balances (bool)"
    )
    parser.add_argument(
        "--fast-fail", default=False, type=bool, help="Generate balances (bool)"
    )
    parser.add_argument(
        "--no-verify", default=False, type=bool, help="Skip verifying results"
    )

    parser.add_argument(
        "--bitcoin-reorg",
        default=False,
        type=bool,
        help="Trigger a Bitcoin chain reorg",
    )

    parser.add_argument(
        "--ethereum-reorg",
        default=False,
        type=bool,
        help="Trigger an Ethereum chain reorg",
    )

    args = parser.parse_args()

    txn_list = "data/smoke_test_native_transactions.json"
    if RUNE.get_chain() == "BNB":
        txn_list = "data/smoke_test_transactions.json"
    with open(txn_list, "r") as f:
        txns = json.load(f)

    health = Health(args.thorchain, args.midgard, args.binance, args.fast_fail)

    smoker = Smoker(
        args.binance,
        args.bitcoin,
        args.ethereum,
        args.thorchain,
        health,
        txns,
        args.generate_balances,
        args.fast_fail,
        args.no_verify,
        args.bitcoin_reorg,
        args.ethereum_reorg,
    )
    try:
        smoker.run()
        sys.exit(smoker.exit)
    except Exception as e:
        logging.error(e)
        logging.exception("Smoke tests failed")
        sys.exit(1)


class Smoker:
    def __init__(
        self,
        bnb,
        btc,
        eth,
        thor,
        health,
        txns,
        gen_balances=False,
        fast_fail=False,
        no_verify=False,
        bitcoin_reorg=False,
        ethereum_reorg=False,
    ):
        self.binance = Binance()
        self.bitcoin = Bitcoin()
        self.ethereum = Ethereum()
        self.thorchain = Thorchain()
        self.thorchain_state = ThorchainState()

        self.health = health

        self.txns = txns

        self.thorchain_client = ThorchainClient(thor, enable_websocket=True)
        pubkey = self.thorchain_client.get_vault_pubkey()

        self.thorchain_state.set_vault_pubkey(pubkey)
        if RUNE.get_chain() == "THOR":
            self.thorchain_state.reserve = 22000000000000000

        self.mock_thorchain = MockThorchain(thor)

        self.mock_bitcoin = MockBitcoin(btc)
        # extract pubkey from bech32 encoded pubkey
        # removing first 5 bytes used by amino encoding
        raw_pubkey = decode_address(pubkey)[5:]
        bitcoin_address = MockBitcoin.get_address_from_pubkey(raw_pubkey)
        self.mock_bitcoin.set_vault_address(bitcoin_address)

        self.mock_ethereum = MockEthereum(eth)
        ethereum_address = MockEthereum.get_address_from_pubkey(raw_pubkey)
        self.mock_ethereum.set_vault_address(ethereum_address)

        self.mock_binance = MockBinance(bnb)
        self.mock_binance.set_vault_address_by_pubkey(raw_pubkey)

        self.generate_balances = gen_balances
        self.fast_fail = fast_fail
        self.no_verify = no_verify
        self.bitcoin_reorg = bitcoin_reorg
        self.ethereum_reorg = ethereum_reorg
        self.thorchain_client.events = []
        self.exit = 0

    def error(self, err):
        self.exit = 1
        if self.fast_fail:
            raise Exception(err)
        else:
            logging.error(err)

    def check_pools(self):
        # compare simulation pools vs real pools
        real_pools = self.thorchain_client.get_pools()
        for rpool in real_pools:
            spool = self.thorchain_state.get_pool(Asset(rpool["asset"]))
            if int(spool.rune_balance) != int(rpool["balance_rune"]):
                self.error(
                    f"Bad Pool-{rpool['asset']} balance: RUNE "
                    f"{spool.rune_balance} != {rpool['balance_rune']}"
                )
                if int(spool.asset_balance) != int(rpool["balance_asset"]):
                    self.error(
                        f"Bad Pool-{rpool['asset']} balance: ASSET "
                        f"{spool.asset_balance} != {rpool['balance_asset']}"
                    )

    def check_binance(self):
        # compare simulation binance vs mock binance
        mock_accounts = self.mock_binance.accounts()
        for macct in mock_accounts:
            for name, address in aliases_bnb.items():
                if name == "MASTER":
                    continue  # don't care to compare MASTER account
                if address == macct["address"]:
                    sacct = self.binance.get_account(address)
                    for bal in macct["balances"]:
                        sim_coin = Coin(
                            f"BNB.{bal['denom']}", sacct.get(f"BNB.{bal['denom']}")
                        )
                        bnb_coin = Coin(f"BNB.{bal['denom']}", bal["amount"])
                        if sim_coin != bnb_coin:
                            self.error(
                                f"Bad binance balance: {name} {bnb_coin} != {sim_coin}"
                            )

    def check_chain(self, chain, mock, reorg):
        # compare simulation bitcoin vs mock bitcoin
        for addr, sim_acct in chain.accounts.items():
            name = get_alias(chain.chain, addr)
            if name == "MASTER":
                continue  # don't care to compare MASTER account
            if name == "VAULT" and chain.chain == "THOR":
                continue  # don't care about vault for thorchain
            mock_coin = Coin(chain.coin, mock.get_balance(addr))
            sim_coin = Coin(chain.coin, sim_acct.get(chain.coin))
            # dont raise error on reorg balance being invalidated
            # sim is not smart enough to subtract funds on reorg
            if mock_coin.amount == 0 and reorg:
                return
            if sim_coin != mock_coin:
                self.error(
                    f"Bad {chain.name} balance: {name} {mock_coin} != {sim_coin}"
                )

    def check_vaults(self):
        # check vault data
        vdata = self.thorchain_client.get_vault_data()
        if int(vdata["total_reserve"]) != self.thorchain_state.reserve:
            sim = self.thorchain_state.reserve
            real = vdata["total_reserve"]
            self.error(f"Mismatching reserves: {sim} != {real}")
        if int(vdata["bond_reward_rune"]) != self.thorchain_state.bond_reward:
            sim = self.thorchain_state.bond_reward
            real = vdata["bond_reward_rune"]
            self.error(f"Mismatching bond reward: {sim} != {real}")

    def check_events(self):
        events = self.thorchain_client.events
        sim_events = self.thorchain_state.events

        if events != sim_events:
            wrong_events = [e for e in events if e not in sim_events]
            wrong_sim_events = [e for e in sim_events if e not in events]
            logging.error(f"THORChain Events {wrong_events}")
            logging.error(f"Simulator Events {wrong_sim_events}")
            self.error("Events mismatch")

    @retry(stop=stop_after_delay(30), wait=wait_fixed(1), reraise=True)
    def run_health(self):
        self.health.run()

    def broadcast_chain(self, txn):
        """
        Broadcast tx to respective chain mock server
        """
        if txn.chain == Binance.chain:
            return self.mock_binance.transfer(txn)
        if txn.chain == Bitcoin.chain:
            return self.mock_bitcoin.transfer(txn)
        if txn.chain == Ethereum.chain:
            return self.mock_ethereum.transfer(txn)
        if txn.chain == MockThorchain.chain:
            return self.mock_thorchain.transfer(txn)

    def broadcast_simulator(self, txn):
        """
        Broadcast tx to simulator state chain
        """
        if txn.chain == Binance.chain:
            return self.binance.transfer(txn)
        if txn.chain == Bitcoin.chain:
            return self.bitcoin.transfer(txn)
        if txn.chain == Ethereum.chain:
            return self.ethereum.transfer(txn)
        if txn.chain == Thorchain.chain:
            return self.thorchain.transfer(txn)

    def set_network_fees(self):
        """
        Retrieve network fees on chain for each txn
        and update thorchain state
        """
        btc = self.mock_bitcoin.block_stats
        fees = {
            "BNB": self.mock_binance.singleton_gas,
            "ETH": self.mock_ethereum.default_gas,
            "BTC": btc["tx_size"] * btc["tx_rate"],
        }
        self.thorchain_state.set_network_fees(fees)
        self.thorchain_state.set_tx_rate(btc["tx_rate"])

    def sim_trigger_tx(self, txn):
        # process transaction in thorchain
        self.set_network_fees()
        outbounds = self.thorchain_state.handle(txn)

        for outbound in outbounds:
            # update simulator state with outbound txs
            self.broadcast_simulator(outbound)

        return outbounds

    def sim_catch_up(self, txn):
        # At this point, we can assume that the transaction on real thorchain
        # has already occurred, and we can now play "catch up" in our simulated
        # thorchain state

        # used to track if we have already processed this txn
        outbounds = []
        processed = False
        pending_txs = 0

        for x in range(0, 30):  # 30 attempts
            events = self.thorchain_client.events[:]
            sim_events = self.thorchain_state.events[:]
            new_events = events[len(sim_events) :]

            # we have more real events than sim, fill in the gaps
            if len(new_events) > 0:
                for evt in new_events:
                    if evt.type == "gas":
                        todo = []
                        # with the given gas pool event data, figure out
                        # which outbound txns are for this gas pool, vs
                        # another later on
                        count = 0
                        for out in outbounds:
                            # a gas pool matches a txn if their from
                            # the same blockchain
                            event_chain = Asset(evt.get("asset")).get_chain()
                            out_chain = out.coins[0].asset.get_chain()
                            if event_chain == out_chain:
                                todo.append(out)
                                count += 1
                                if count >= int(evt.get("transaction_count")):
                                    break
                        self.thorchain_state.handle_gas(todo)

                    elif evt.type == "rewards":
                        self.thorchain_state.handle_rewards()

                    elif evt.type == "outbound" and processed and pending_txs > 0:
                        # figure out which outbound event is which tx
                        for out in outbounds:
                            if out.coins_str() == evt.get("coin"):
                                self.thorchain_state.generate_outbound_events(
                                    txn, [out]
                                )
                                pending_txs -= 1

                    elif not processed:
                        outbounds = self.sim_trigger_tx(txn)
                        pending_txs = len(outbounds)
                        processed = True
                continue

            # we have same count of events but its a cross chain stake
            elif txn.is_cross_chain_stake() and not processed:
                outbounds = self.sim_trigger_tx(txn)
                pending_txs = len(outbounds)
                processed = True
                time.sleep(6)  # need to wait for thorchain to handle it
                continue

            if len(events) == len(sim_events) and pending_txs <= 0 and processed:
                break

            time.sleep(1)

        if pending_txs > 0:
            msg = f"failed to send all outbound transactions {pending_txs}"
            self.error(msg)
        return outbounds

    def log_result(self, tx, outbounds):
        """
        Log result after a tx was processed
        """
        if len(outbounds) == 0:
            return
        result = "[+]"
        if "REFUND" in outbounds[0].memo:
            result = "[-]"
        for outbound in outbounds:
            logging.info(f"{result} {outbound.short()}")

    def run(self):
        for i, txn in enumerate(self.txns):
            txn = Transaction.from_dict(txn)

            if self.bitcoin_reorg:
                # get block hash from bitcoin we are going to invalidate later
                if i == 14 or i == 24:
                    current_height = self.mock_bitcoin.get_block_height()
                    block_hash = self.mock_bitcoin.get_block_hash(current_height)
                    logging.info(f"Block to invalidate {current_height} {block_hash}")

                # now we processed some btc txs and we invalidate an older block
                # to make those txs not valid anymore and test thornode reaction
                if i == 18 or i == 28:
                    self.mock_bitcoin.invalidate_block(block_hash)
                    logging.info("Reorg triggered")

            if self.ethereum_reorg:
                # get block hash from ethereum we are going to invalidate later
                if i == 14 or i == 24:
                    current_height = self.mock_ethereum.get_block_height()
                    block_hash = self.mock_ethereum.get_block_hash(current_height)
                    logging.info(f"Block to invalidate {current_height} {block_hash}")

                # now we processed some eth txs and we invalidate an older block
                # to make those txs not valid anymore and test thornode reaction
                if i == 18 or i == 28:
                    self.mock_ethereum.set_block(current_height)
                    logging.info("Reorg triggered")

            logging.info(f"{i:2} {txn}")

            self.broadcast_chain(txn)
            self.broadcast_simulator(txn)

            if txn.memo == "SEED":
                continue

            outbounds = self.sim_catch_up(txn)

            # check if we are verifying the results
            if self.no_verify:
                continue

            self.check_events()
            self.check_pools()

            self.check_binance()
            self.check_chain(self.bitcoin, self.mock_bitcoin, self.bitcoin_reorg)
            self.check_chain(self.ethereum, self.mock_ethereum, self.ethereum_reorg)

            if RUNE.get_chain() == "THOR":
                self.check_chain(self.thorchain, self.mock_thorchain, None)

            self.check_vaults()
            self.run_health()

            self.log_result(txn, outbounds)


if __name__ == "__main__":
    main()
