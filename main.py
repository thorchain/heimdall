#!/bin/python

import json
from deepdiff import DeepDiff

from chains import Binance
from thorchain import ThorchainState
from breakpoint import Breakpoint

from transaction import Transaction
from coin import Coin

txns = [
    # Seeding
    Transaction(Binance.chain, "MASTER", "MASTER",
        [Coin("BNB", 49730000), Coin("RUNE-A1F", 100000000000), Coin("LOK-3C0", 0)], 
    "SEED"),
    Transaction(Binance.chain, "MASTER", "USER-1",
        [Coin("BNB", 50000000), Coin("RUNE-A1F", 50000000000), Coin("LOK-3C0", 50000000000)], 
    "SEED"),
    Transaction(Binance.chain, "MASTER", "STAKER-1",
        [Coin("BNB", 200000000), Coin("RUNE-A1F", 100000000000), Coin("LOK-3C0", 40000000000)], 
    "SEED"),
    Transaction(Binance.chain, "MASTER", "STAKER-2",
        [Coin("BNB", 200000000), Coin("RUNE-A1F", 50000000000), Coin("LOK-3C0", 10000000000)], 
    "SEED"),

    # Staking
    Transaction(Binance.chain, "STAKER-1", "VAULT",
        [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
    "STAKE:BNB.BNB")
]

def get_balance(idx):
    with open('data/balances.json') as f:
        balances = json.load(f)
        for bal in balances:
            if idx == bal['TX']:
                return bal
    raise Exception("could not find idx")

def main():
    bnb = Binance()
    thorchain = ThorchainState()

    for i, txn in enumerate(txns):
        out = 0 # number of outbound transaction to be expected
        if txn.memo == "SEED":
            bnb.seed(txn.toAddress, txn.coins)
            continue
        else:
            bnb.transfer(txn) # send transfer on binance chain
            _, out = thorchain.handle(txn) # process transaction in thorchain

        # generated a snapshop picture of thorchain and bnb
        snap = Breakpoint(thorchain, bnb).snapshot(i, out)
        expected = get_balance(i) # get the expected balance from json file

        diff = DeepDiff(expected, snap, ignore_order=True) # empty dict if are equal
        if len(diff) > 0:
            print(diff)
            raise Exception("did not match!")

if __name__ == "__main__":
    main()
