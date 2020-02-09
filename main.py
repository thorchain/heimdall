#!/bin/python

from chains import Binance
from transaction import Transaction
from coin import Coin

def main():
    txn = Transaction(Binance.chain, "bnb1", "bnb2", Coin("BNB", 25), "my memo")
    print(txn)

if __name__ == "__main__":
    main()
