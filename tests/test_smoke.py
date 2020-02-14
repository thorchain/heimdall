import unittest
import os
import logging
import json
from pprint import pformat
from deepdiff import DeepDiff

from chains import Binance
from thorchain import ThorchainState
from breakpoint import Breakpoint

from smoke import txns


def get_balance(idx):
    """
    Retrieve expected balance with given id
    """
    with open("data/balances.json") as f:
        balances = json.load(f)
        for bal in balances:
            if idx == bal["TX"]:
                return bal
    raise Exception("could not find idx")


class TestSmoke(unittest.TestCase):
    """
    This runs tests with a pre-determined list of transactions and an expected
    balance after each transaction (/data/balance.json). These transactions and
    balances were determined earlier via a google spreadsheet
    https://docs.google.com/spreadsheets/d/1sLK0FE-s6LInWijqKgxAzQk2RiSDZO1GL58kAD62ch0/edit#gid=439437407
    """

    def test_smoke(self):
        export = os.environ.get("EXPORT", None)
        failure = False
        snaps = []
<<<<<<< HEAD
        bnb = Binance()  # init local binance chain
        thorchain = ThorchainState()  # init local thorchain
=======
        bnb = Binance() # init local binance chain
        thorchain = ThorchainState() # init local thorchain 
>>>>>>> support updating balances.json

        for i, txn in enumerate(txns):
            logging.info(f"{i} {txn}")
            if txn.memo == "SEED":
                bnb.seed(txn.toAddress, txn.coins)
                continue
            else:
                bnb.transfer(txn)  # send transfer on binance chain
                outbound = thorchain.handle(txn)  # process transaction in thorchain
                outbound = thorchain.handle_fee(outbound)
                for txn in outbound:
                    gas = bnb.transfer(txn)  # send outbound txns back to Binance
                    thorchain.handle_gas(gas)  # subtract gas from pool(s)

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

        if export:
            with open(export, "w") as fp:
                json.dump(snaps, fp, indent=4)

        if failure:
            raise Exception("Fail")


if __name__ == "__main__":
    unittest.main()
