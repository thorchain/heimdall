import unittest

import json
import pprint
from deepdiff import DeepDiff

from chains import Binance
from thorchain import ThorchainState
from breakpoint import Breakpoint

from transaction import Transaction
from coin import Coin

# A list of [inbound txn, expected # of outbound txns]
txns = [
    # Seeding
    [Transaction(Binance.chain, "MASTER", "MASTER",
        [Coin("BNB", 49730000), Coin("RUNE-A1F", 100000000000), Coin("LOK-3C0", 0)], 
    "SEED"), 0],
    [Transaction(Binance.chain, "MASTER", "USER-1",
        [Coin("BNB", 50000000), Coin("RUNE-A1F", 50000000000), Coin("LOK-3C0", 50000000000)], 
    "SEED"), 0],
    [Transaction(Binance.chain, "MASTER", "STAKER-1",
        [Coin("BNB", 200000000), Coin("RUNE-A1F", 100000000000), Coin("LOK-3C0", 40000000000)], 
    "SEED"), 0],
    [Transaction(Binance.chain, "MASTER", "STAKER-2",
        [Coin("BNB", 200000000), Coin("RUNE-A1F", 50000000000), Coin("LOK-3C0", 10000000000)], 
    "SEED"), 0],

    # Staking
    [Transaction(Binance.chain, "STAKER-1", "VAULT",
        [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
    "STAKE:BNB.BNB"), 0],
    [Transaction(Binance.chain, "STAKER-1", "VAULT",
        [Coin("LOK-3C0", 40000000000), Coin("RUNE-A1F", 50000000000)],
    "STAKE:BNB.LOK-3C0"), 0],
    [Transaction(Binance.chain, "STAKER-2", "VAULT",
        [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
    ""), 2],
    [Transaction(Binance.chain, "STAKER-2", "VAULT",
        [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
    "ABDG?"), 2],
    [Transaction(Binance.chain, "STAKER-2", "VAULT",
        [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
    "STAKE:"), 2],
    [Transaction(Binance.chain, "STAKER-2", "VAULT",
        [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
    "STAKE:BNB.TCAN-014"), 2],
    [Transaction(Binance.chain, "STAKER-2", "VAULT",
        [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
    "STAKE:RUNE-A1F"), 2],
    [Transaction(Binance.chain, "STAKER-2", "VAULT",
        [Coin("BNB", 30000000)],
    "STAKE:BNB.BNB"), 0],
    [Transaction(Binance.chain, "STAKER-2", "VAULT",
        [Coin("RUNE-A1F", 10000000000)],
    "STAKE:BNB.BNB"), 0],
    [Transaction(Binance.chain, "STAKER-2", "VAULT",
        [Coin("BNB", 90000000), Coin("RUNE-A1F", 30000000000)],
    "STAKE:BNB.BNB"), 0],

    # Adding
    [Transaction(Binance.chain, "STAKER-2", "VAULT",
        [Coin("BNB", 30000000), Coin("RUNE-A1F", 5000000000)],
    "ADD:BNB.BNB"), 0],

    # Misc
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("RUNE-A1F", 100000000)],
    " "), 1],
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("RUNE-A1F", 100000000)],
    "ABDG?"), 1],

    # Swaps
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("BNB", 1)],
    "SWAP:BNB.BNB"), 1],
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("BNB", 30000000)],
    "SWAP:BNB.BNB"), 1],
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("BNB", 30000000), Coin("RUNE-A1F", 100000000)],
    "SWAP:BNB.BNB"), 1],
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("RUNE-A1F", 1)],
    "SWAP:BNB.BNB"), 1],
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("RUNE-A1F", 10000000000)],
    "SWAP:BNB.BNB::26572599"), 1],
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("RUNE-A1F", 10000000000)],
    "SWAP:BNB.BNB"), 1],
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("BNB", 10000000)],
    "SWAP:BNB.RUNE-A1F"), 1],
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("RUNE-A1F", 10000000000)],
    "SWAP:BNB.BNB:STAKER-1:23853375"), 1],
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("RUNE-A1F", 10000000000)],
    "SWAP:BNB.BNB:STAKER-1:22460886"), 1],
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("BNB", 10000000)],
    "SWAP:BNB.RUNE-A1F:bnbSTAKER-1"), 1],
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("LOK-3C0", 5000000000)],
    "SWAP:BNB.RUNE-A1F"), 1],
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("RUNE-A1F", 5000000000)],
    "SWAP:BNB.LOK-3C0"), 1],
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("LOK-3C0", 5000000000)],
    "SWAP:BNB.BNB"), 1],
    [Transaction(Binance.chain, "USER-1", "VAULT",
        [Coin("BNB", 5000000)],
    "SWAP:BNB.LOK-3C0"), 1],

    # Unstaking (withdrawing)
    [Transaction(Binance.chain, "STAKER-1", "VAULT",
        [Coin("BNB", 1)],
    "WITHDRAW:BNB.BNB:5000"), 2],
    [Transaction(Binance.chain, "STAKER-1", "VAULT",
        [Coin("BNB", 1)],
    "WITHDRAW:BNB.BNB:10000"), 2],
    [Transaction(Binance.chain, "STAKER-2", "VAULT",
        [Coin("BNB", 1)],
    "WITHDRAW:BNB.BNB"), 2],
    [Transaction(Binance.chain, "STAKER-1", "VAULT",
        [Coin("BNB", 1)],
    "WITHDRAW:BNB.LOK-3C0"), 2],
]

def get_balance(idx):
    with open('data/balances.json') as f:
        balances = json.load(f)
        for bal in balances:
            if idx == bal['TX']:
                return bal
    raise Exception("could not find idx")

class TestRun(unittest.TestCase):
    def test_run(self):
        bnb = Binance()
        thorchain = ThorchainState()

        for i, unit in enumerate(txns):
            txn, out = unit
            print("{} {}".format(i, txn))
            if txn.memo == "SEED":
                bnb.seed(txn.toAddress, txn.coins)
                continue
            else:
                bnb.transfer(txn) # send transfer on binance chain
                outbound = thorchain.handle(txn) # process transaction in thorchain
                for txn in outbound:
                    gas = bnb.transfer(txn) # send outbound txns back to Binance
                    thorchain.handle_gas(gas) # subtract gas from pool(s)

            # generated a snapshop picture of thorchain and bnb
            snap = Breakpoint(thorchain, bnb).snapshot(i, out)
            expected = get_balance(i) # get the expected balance from json file

            diff = DeepDiff(snap, expected, ignore_order=True) # empty dict if are equal
            if len(diff) > 0:
                print("Transaction:", i, txn)
                print(">>>>>> Expected")
                pprint.pprint(expected)
                print(">>>>>> Obtained")
                pprint.pprint(snap)
                print(">>>>>> DIFF")
                pprint.pprint(diff)
                raise Exception("did not match!")


if __name__ == '__main__':
    unittest.main()
