import argparse
import logging
import os
import time
import sys
import json

from tenacity import retry, stop_after_attempt, wait_fixed

from chains import Binance, MockBinance
from thorchain import ThorchainState, ThorchainClient, Event
from health import Health
from common import Transaction, Coin, Asset

# Init logging
logging.basicConfig(
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    level=os.environ.get("LOGLEVEL", "INFO"),
)


def log_health_retry(retry_state):
    logging.warning(
        "Health checks failed, waiting for Midgard to query new events and retry..."
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binance", default="http://localhost:26660", help="Mock binance server"
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

    with open("data/smoke_test_transactions.json", "r") as f:
        txns = json.load(f)

    health = Health(args.thorchain, args.midgard, args.binance)

    smoker = Smoker(
        args.binance,
        args.thorchain,
        health,
        txns,
        args.generate_balances,
        args.fast_fail,
        args.no_verify,
    )
    try:
        smoker.run()
        sys.exit(smoker.exit)
    except Exception as e:
        logging.fatal(e)
        sys.exit(1)


class Smoker:
    def __init__(
        self,
        bnb,
        thor,
        health,
        txns,
        gen_balances=False,
        fast_fail=False,
        no_verify=False,
    ):
        self.binance = Binance()
        self.thorchain = ThorchainState()

        self.health = health

        self.txns = txns

        self.thorchain_client = ThorchainClient(thor)
        vault_address = self.thorchain_client.get_vault_address()
        vault_pubkey = self.thorchain_client.get_vault_pubkey()

        self.thorchain.set_vault_pubkey(vault_pubkey)

        self.mock_binance = MockBinance(bnb)
        self.mock_binance.set_vault_address(vault_address)

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
                    f"Bad pool rune balance: {rpool['asset']} "
                    f"{spool.rune_balance} != {rpool['balance_rune']}"
                )
                if int(spool.asset_balance) != int(rpool["balance_asset"]):
                    self.error(
                        f"Bad pool asset balance: {rpool['asset']} "
                        f"{spool.asset_balance} != {rpool['balance_asset']}"
                    )

    def check_binance(self):
        # compare simulation binance vs mock binance
        mockAccounts = self.mock_binance.accounts()
        for macct in mockAccounts:
            for name, address in self.mock_binance.aliases.items():
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

        # check ordered events
        for event, sim_event in zip(events, sim_events):
            if sim_event != event:
                logging.error(
                    f"Event Thorchain {event} \n   !="
                    f"  \nEvent Simulator {sim_event}"
                )
                self.error("Events mismatch")

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_fixed(1),
        reraise=True,
        after=log_health_retry,
    )
    def run_health(self):
        self.health.run()

    def run(self):
        for i, txn in enumerate(self.txns):
            txn = Transaction.from_dict(txn)

            logging.info(f"{i} {txn}")

            self.mock_binance.transfer(txn)  # trigger mock Binance transaction
            self.binance.transfer(txn)  # send transfer on binance chain

            if txn.memo == "SEED":
                continue

            outbounds = self.thorchain.handle(txn)  # process transaction in thorchain
            outbounds = self.thorchain.handle_fee(outbounds)

            # replicate order of outbounds broadcast from thorchain
            self.thorchain.order_outbound_txns(outbounds)

            for outbound in outbounds:
		# update binance simulator state with outbound txs
                gas = self.binance.transfer(
                    outbound
                )  
                outbound.gas = [gas]

            self.thorchain.handle_rewards()
            self.thorchain.handle_gas(outbounds)
            self.thorchain.handle_gas_reimburse()

            # wait for blocks to be processed on real chains
            self.mock_binance.wait_for_blocks(len(outbounds))
            self.thorchain_client.wait_for_blocks(2)

            # check if we are verifying the results
            if self.no_verify:
                continue

            self.check_pools()
            self.check_binance()
            self.check_vaults()
            self.check_events()
            self.run_health()


if __name__ == "__main__":
    main()
