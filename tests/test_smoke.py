import unittest
import os
import logging
import json
from pprint import pformat
from deepdiff import DeepDiff

from chains.binance import Binance
from chains.bitcoin import Bitcoin
from chains.ethereum import Ethereum
from thorchain.thorchain import ThorchainState, Event
from utils.breakpoint import Breakpoint
from utils.common import Transaction

# Init logging
logging.basicConfig(
    format="%(asctime)s | %(levelname).4s | %(message)s",
    level=os.environ.get("LOGLEVEL", "INFO"),
)


def get_balance(idx):
    """
    Retrieve expected balance with given id
    """
    with open("data/smoke_test_balances.json") as f:
        balances = json.load(f)
        for bal in balances:
            if idx == bal["TX"]:
                return bal


def get_events():
    """
    Retrieve expected events
    """
    with open("data/smoke_test_events.json") as f:
        events = json.load(f)
        return [Event.from_dict(evt) for evt in events]
    raise Exception("could not load events")


class TestSmoke(unittest.TestCase):
    """
    This runs tests with a pre-determined list of transactions and an expected
    balance after each transaction (/data/balance.json). These transactions and
    balances were determined earlier via a google spreadsheet
    https://docs.google.com/spreadsheets/d/1sLK0FE-s6LInWijqKgxAzQk2RiSDZO1GL58kAD62ch0/edit#gid=439437407
    """

    def test_smoke(self):
        export = os.environ.get("EXPORT", None)
        export_events = os.environ.get("EXPORT_EVENTS", None)

        failure = False
        snaps = []
        bnb = Binance()  # init local binance chain
        btc = Bitcoin()  # init local bitcoin chain
        eth = Ethereum()  # init local ethereum chain
        thorchain = ThorchainState()  # init local thorchain

        with open("data/smoke_test_transactions.json", "r") as f:
            loaded = json.load(f)

        for i, txn in enumerate(loaded):
            txn = Transaction.from_dict(txn)
            logging.info(f"{i} {txn}")

            if txn.chain == Binance.chain:
                bnb.transfer(txn)  # send transfer on binance chain
            if txn.chain == Bitcoin.chain:
                btc.transfer(txn)  # send transfer on bitcoin chain
            if txn.chain == Ethereum.chain:
                eth.transfer(txn)  # send transfer on ethereum chain

            if txn.memo == "SEED":
                continue

            outbound = thorchain.handle(txn)  # process transaction in thorchain
            outbound = thorchain.handle_fee(outbound)
            thorchain.order_outbound_txns(outbound)

            for txn in outbound:
                if txn.chain == Binance.chain:
                    bnb.transfer(txn)  # send outbound txns back to Binance
                if txn.chain == Bitcoin.chain:
                    btc.transfer(txn)  # send outbound txns back to Bitcoin
                if txn.chain == Ethereum.chain:
                    eth.transfer(txn)  # send outbound txns back to Ethereum

            thorchain.handle_rewards()

            bnbOut = []
            for out in outbound:
                if out.coins[0].asset.get_chain() == "BNB":
                    bnbOut.append(out)
            btcOut = []
            for out in outbound:
                if out.coins[0].asset.get_chain() == "BTC":
                    btcOut.append(out)
            ethOut = []
            for out in outbound:
                if out.coins[0].asset.get_chain() == "ETH":
                    ethOut.append(out)
            thorchain.handle_gas(bnbOut)  # subtract gas from pool(s)
            thorchain.handle_gas(btcOut)  # subtract gas from pool(s)
            thorchain.handle_gas(ethOut)  # subtract gas from pool(s)

            # generated a snapshop picture of thorchain and bnb
            snap = Breakpoint(thorchain, bnb).snapshot(i, len(outbound))
            snaps.append(snap)
            expected = get_balance(i)  # get the expected balance from json file

            diff = DeepDiff(
                snap, expected, ignore_order=True
            )  # empty dict if are equal
            if len(diff) > 0:
                logging.info(f"Transaction: {i} {txn}")
                logging.info(">>>>>> Expected")
                logging.info(pformat(expected))
                logging.info(">>>>>> Obtained")
                logging.info(pformat(snap))
                logging.info(">>>>>> DIFF")
                logging.info(pformat(diff))
                if not export:
                    raise Exception("did not match!")

        # check events against expected
        expected_events = get_events()
        for event, expected_event in zip(thorchain.events, expected_events):
            if event != expected_event:
                logging.error(
                    f"Event Thorchain {event} \n   !="
                    f"  \nEvent Expected {expected_event}"
                )
                if not export_events:
                    raise Exception("Events mismatch")

        if export:
            with open(export, "w") as fp:
                json.dump(snaps, fp, indent=4)

        if export_events:
            with open(export_events, "w") as fp:
                json.dump(thorchain.events, fp, default=lambda x: x.__dict__, indent=4)

        if failure:
            raise Exception("Fail")


if __name__ == "__main__":
    unittest.main()
