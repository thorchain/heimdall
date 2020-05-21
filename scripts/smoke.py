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
from chains.thorchain import ThorchainSigner
from thorchain.thorchain import ThorchainState, ThorchainClient, Event
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
        "--thorchain-websocket",
        default="ws://localhost:26657/websocket",
        help="Thorchain Websocket url",
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

    with open("data/smoke_test_transactions.json", "r") as f:
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
        args.thorchain_websocket,
    )
    try:
        smoker.run()
        sys.exit(smoker.exit)
    except Exception:
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
        thor_websocket=None,
    ):
        self.binance = Binance()
        self.bitcoin = Bitcoin()
        self.ethereum = Ethereum()
        self.thorchain = ThorchainState()

        self.health = health

        self.txns = txns

        self.thorchain_client = ThorchainClient(thor, thor_websocket)
        pubkey = self.thorchain_client.get_vault_pubkey()

        self.thorchain.set_vault_pubkey(pubkey)
        if RUNE.split(".")[0] == "THOR":
            self.thorchain.reserve = 22000000000000000

        self.thorchain_signer = ThorchainSigner(thor)

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
            spool = self.thorchain.get_pool(Asset(rpool["asset"]))
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

    def check_bitcoin(self):
        # compare simulation bitcoin vs mock bitcoin
        for addr, sim_acct in self.bitcoin.accounts.items():
            name = get_alias(Bitcoin.chain, addr)
            if name == "MASTER":
                continue  # don't care to compare MASTER account
            mock_coin = Coin("BTC.BTC", self.mock_bitcoin.get_balance(addr))
            sim_coin = Coin("BTC.BTC", sim_acct.get("BTC.BTC"))
            # dont raise error on reorg balance being invalidated
            # sim is not smart enough to subtract funds on reorg
            if mock_coin.amount == 0 and self.bitcoin_reorg:
                return
            if sim_coin != mock_coin:
                self.error(f"Bad bitcoin balance: {name} {mock_coin} != {sim_coin}")

    def check_ethereum(self):
        # compare simulation ethereum vs mock ethereum
        for addr, sim_acct in self.ethereum.accounts.items():
            name = get_alias(Ethereum.chain, addr)
            if name == "MASTER":
                continue  # don't care to compare MASTER account
            mock_coin = Coin("ETH.ETH", self.mock_ethereum.get_balance(addr))
            sim_coin = Coin("ETH.ETH", sim_acct.get("ETH.ETH"))
            # dont raise error on reorg balance being invalidated
            # sim is not smart enough to subtract funds on reorg
            if mock_coin.amount == 0 and self.ethereum_reorg:
                return
            if sim_coin != mock_coin:
                self.error(f"Bad ethereum balance: {name} {mock_coin} != {sim_coin}")

    def check_vaults(self):
        # check vault data
        vdata = self.thorchain_client.get_vault_data()
        if int(vdata["total_reserve"]) != self.thorchain.reserve:
            sim = self.thorchain.reserve
            real = vdata["total_reserve"]
            self.error(f"Mismatching reserves: {sim} != {real}")
        if int(vdata["bond_reward_rune"]) != self.thorchain.bond_reward:
            sim = self.thorchain.bond_reward
            real = vdata["bond_reward_rune"]
            self.error(f"Mismatching bond reward: {sim} != {real}")

    def check_sdk_events(self):
        events = self.thorchain_client.get_sdk_events()
        sim_events = self.thorchain.sdk_events

        # TODO remove when we switch to SDK events only
        if len(events) != len(sim_events):
            return

        for event, sim_event in zip(sorted(events), sorted(sim_events)):
            if sim_event != event:
                logging.error(
                    f"Event Thorchain \n{event} \n   !="
                    f"  \nEvent Simulator \n{sim_event}"
                )
                self.error("Events SDK mismatch")

    def check_events(self):
        # compare simulation events with real events
        raw_events = self.thorchain_client.get_events()
        # convert to Event objects
        events = [Event.from_dict(evt) for evt in raw_events]

        # get simulator events
        sim_events = self.thorchain.get_events()

        # check events
        for event, sim_event in zip(events, sim_events):
            if sim_event != event:
                logging.error(
                    f"Event Thorchain {event} \n   !="
                    f"  \nEvent Simulator {sim_event}"
                )
                self.error("Events mismatch")

    @retry(stop=stop_after_delay(60), wait=wait_fixed(1), reraise=True)
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
        if txn.chain == ThorchainSigner.chain:
            return self.thorchain_signer.transfer(txn)

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

    def sim_catch_up(self, txn):
        # At this point, we can assume that the transaction on real thorchain
        # has already occurred, and we can now play "catch up" in our simulated
        # thorchain state

        # used to track if we have already processed this txn
        processed_transaction = False
        outbounds = []
        # keep track of how many outbound txs we created this inbound txn
        count_outbounds = 0

        for x in range(0, 30):  # 30 attempts
            events = self.thorchain_client.get_events()
            events = [Event.from_dict(evt) for evt in events]
            evt_list = [evt.type for evt in events]  # convert evts to array of strings

            sim_events = self.thorchain.get_events()
            sim_evt_list = [
                evt.type for evt in sim_events
            ]  # convert evts to array of strings

            # we have more real events than sim, fill in the gaps
            if len(events) > len(sim_events):
                for evt in events[len(sim_events) :]:
                    if evt.type == "gas":
                        todo = []
                        # with the given gas pool event data, figure out
                        # which outbound txns are for this gas pool, vs
                        # another later on
                        for pool in evt.event.pools:
                            count = 0
                            for out in outbounds:
                                # a gas pool matches a txn if their from
                                # the same blockchain
                                p_chain = pool.asset.get_chain()
                                c_chain = out.coins[0].asset.get_chain()
                                if p_chain == c_chain:
                                    todo.append(out)
                                    count += 1
                                    if count >= pool.transaction_count:
                                        break
                        self.thorchain.handle_gas(todo)
                        # countdown til we've seen all expected gas evts
                        count_outbounds -= len(todo)

                    elif evt.type == "rewards":
                        self.thorchain.handle_rewards()

                    else:
                        # sent a transaction to our simulated thorchain
                        outbounds = self.thorchain.handle(txn)
                        # process transaction in thorchain
                        outbounds = self.thorchain.handle_fee(txn, outbounds)
                        # we have now processed this inbound txn
                        processed_transaction = True

                        # replicate order of outbounds broadcast from thorchain
                        self.thorchain.order_outbound_txns(outbounds)

                        # expecting to see this many outbound txs
                        count_outbounds = 0
                        for o in outbounds:
                            if o.chain == "THOR":
                                continue  # thorchain transactions are on chain
                            pool = self.thorchain.get_pool(o.coins[0].asset)
                            if pool.rune_balance == 0:
                                continue  # no pool exists, skip it
                            count_outbounds += 1

                        for outbound in outbounds:
                            # update simulator state with outbound txs
                            self.broadcast_simulator(outbound)

                        self.thorchain.generate_outbound_events(txn, outbounds)
                continue

            # happy path exit
            if (
                evt_list == sim_evt_list
                and count_outbounds <= 0
                and processed_transaction
            ):
                break
            # unhappy path exit. We got the events in a different order
            if len(evt_list) == len(sim_evt_list) and evt_list != sim_evt_list:
                break

            time.sleep(1)

        if count_outbounds > 0:
            self.error(
                f"failed to send out all outbound transactions ({count_outbounds})"
            )

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

            self.sim_catch_up(txn)

            # check if we are verifying the results
            if self.no_verify:
                continue

            # self.check_sdk_events()
            self.check_events()
            self.check_pools()
            self.check_binance()
            self.check_bitcoin()
            self.check_ethereum()
            self.check_vaults()
            self.run_health()


if __name__ == "__main__":
    main()
