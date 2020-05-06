import argparse
import logging
import os
import time
import sys
import json

from tenacity import retry, stop_after_attempt, wait_fixed

from utils.segwit_addr import decode_address
from chains.binance import Binance, MockBinance
from chains.bitcoin import Bitcoin, MockBitcoin
from thorchain.thorchain import ThorchainState, ThorchainClient, Event
from scripts.health import Health
from utils.common import Transaction, Coin, Asset
from chains.aliases import aliases_bnb, get_alias

# Init logging
logging.basicConfig(
    format="%(asctime)s | %(levelname).4s | %(message)s",
    level=os.environ.get("LOGLEVEL", "INFO"),
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binance", default="http://localhost:26660", help="Mock binance server"
    )
    parser.add_argument(
        "--bitcoin",
        default="http://thorchain:password@localhost:18443",
        help="Regtest bitcoin server",
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

    args = parser.parse_args()

    with open("data/bitcoin_reorg_test_transactions.json", "r") as f:
        txns = json.load(f)

    health = Health(args.thorchain, args.midgard, args.binance, args.fast_fail)

    bitcoin_reorg = BitcoinReorg(
        args.binance,
        args.bitcoin,
        args.thorchain,
        health,
        txns,
        args.generate_balances,
        args.fast_fail,
        args.no_verify,
    )
    try:
        bitcoin_reorg.run()
        sys.exit(bitcoin_reorg.exit)
    except Exception as e:
        logging.fatal(e)
        raise e
        sys.exit(1)


class BitcoinReorg:
    def __init__(
        self,
        bnb,
        btc,
        thor,
        health,
        txns,
        gen_balances=False,
        fast_fail=False,
        no_verify=False,
    ):
        self.binance = Binance()
        self.bitcoin = Bitcoin()
        self.thorchain = ThorchainState()

        self.health = health

        self.txns = txns

        self.thorchain_client = ThorchainClient(thor)
        vault_address = self.thorchain_client.get_vault_address()
        vault_pubkey = self.thorchain_client.get_vault_pubkey()

        self.thorchain.set_vault_pubkey(vault_pubkey)

        self.mock_binance = MockBinance(bnb)
        self.mock_binance.set_vault_address(vault_address)

        self.mock_bitcoin = MockBitcoin(btc)
        # extract pubkey from bech32 encoded pubkey
        # removing first 5 bytes used by amino encoding
        raw_pubkey = decode_address(vault_pubkey)[5:]
        bitcoin_address = MockBitcoin.get_address_from_pubkey(raw_pubkey)
        self.mock_bitcoin.set_vault_address(bitcoin_address)

        self.generate_balances = gen_balances
        self.fast_fail = fast_fail
        self.no_verify = no_verify
        self.exit = 0

        time.sleep(5)  # give thorchain extra time to start the blockchain

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
                        sim_coin = Coin(bal["denom"], sacct.get(bal["denom"]))
                        bnb_coin = Coin(bal["denom"], bal["amount"])
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
            if sim_coin != mock_coin:
                self.error(f"Bad bitcoin balance: {name} {mock_coin} != {sim_coin}")

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

    @retry(stop=stop_after_attempt(10), wait=wait_fixed(1), reraise=True)
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

    def broadcast_simulator(self, txn):
        """
        Broadcast tx to simulator state chain
        """
        if txn.chain == Binance.chain:
            return self.binance.transfer(txn)
        if txn.chain == Bitcoin.chain:
            return self.bitcoin.transfer(txn)

    def sim_catch_up(self, txn):
        # At this point, we can assume that the transaction on real thorchain
        # has already occurred, and we can now play "catch up" in our simulated
        # thorchain state

        # used to track if we have already processed this txn
        processed_transaction = False
        outbounds = []
        # keep track of how many outbound txs we created this inbound txn
        count_outbounds = 0

        for x in range(0, 60):  # 60 attempts
            events = self.thorchain_client.get_events()
            events = [Event.from_dict(evt) for evt in events]
            evt_list = [evt.type for evt in events]  # convert evts to array of strings

            sim_events = self.thorchain.get_events()
            sim_evt_list = [
                evt.type for evt in sim_events
            ]  # convert evts to array of strings

            if len(events) > len(
                sim_events
            ):  # we have more real events than sim, fill in the gaps
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
                                    if count >= pool.count:
                                        break
                        self.thorchain.handle_gas(todo)
                        # countdown til we've seen all expected gas evts
                        count_outbounds -= len(todo)

                    elif evt.type == "rewards":
                        self.thorchain.handle_rewards()

                    else:
                        # sent a transaction to our simulated thorchain
                        outbounds = self.thorchain.handle(
                            txn
                        )  # process transaction in thorchain
                        outbounds = self.thorchain.handle_fee(outbounds)
                        processed_transaction = (
                            True  # we have now processed this inbound txn
                        )
                        count_outbounds = len(
                            outbounds
                        )  # expecting to see this many outbound txs

                        # replicate order of outbounds broadcast from thorchain
                        self.thorchain.order_outbound_txns(outbounds)

                        for outbound in outbounds:
                            # update simulator state with outbound txs
                            self.broadcast_simulator(outbound)
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

        if count_outbounds != 0:
            self.error(
                f"failed to send out all outbound transactions ({count_outbounds})"
            )

    def run(self):
        for i, txn in enumerate(self.txns):
            txn = Transaction.from_dict(txn)

            logging.info(f"{i:2} {txn}")

            # get block hash from bitcoin we are going to invalidate later
            if i == 10:
                current_height = self.mock_bitcoin.get_block_height()
                block_hash = self.mock_bitcoin.get_block_hash(current_height)
                logging.info(f"Block to invalidated {current_height} {block_hash}")

            # now we processed some btc txs and we invalidate an older block
            # to make those txs not valid anymore and test thornode reaction
            if i == 12:
                self.mock_bitcoin.invalidate_block(block_hash)
                logging.info("Reorg triggered")

            self.broadcast_chain(txn)
            self.broadcast_simulator(txn)

            if txn.memo == "SEED":
                continue

            self.sim_catch_up(txn)

            # check if we are verifying the results
            if self.no_verify:
                continue

            self.check_events()
            self.check_pools()
            self.check_binance()
            self.check_bitcoin()
            self.check_vaults()
            self.run_health()


if __name__ == "__main__":
    main()
