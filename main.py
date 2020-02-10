#!/bin/python

from chains import Binance
from thorchain import ThorchainState

from transaction import Transaction
from coin import Coin

txns = [
    Transaction(Binance.chain, "STAKER-1", "VAULT", [Coin("BNB", 150000000), Coin("RUNE", 50000000000)], "STAKE:BNB.BNB")
]

def main():
    bnb = Binance()
    thorchain = ThorchainState()

    # seed funds
    bnb.seed("USER-1", [
        Coin("RUNE_A1F", 50000000000),
        Coin("BNB", 50000000000),
        Coin("LOKI-3C0", 50000000000),
    ])
    bnb.seed("STAKER-1", [
        Coin("RUNE_A1F", 100000000000),
        Coin("BNB", 200000000),
        Coin("LOKI-3C0", 40000000000),
    ])
    bnb.seed("STAKER-2", [
        Coin("RUNE_A1F", 50000000000),
        Coin("BNB", 200000000),
        Coin("LOKI-3C0", 10000000000),
    ])

    for txn in txns:
        bnb.transfer(txn)
        thorchain.handle(txn)


if __name__ == "__main__":
    main()
