#!/bin/python

from transaction import Transaction
from coin import Coin

def main():
    txn = Transaction("bnb1", "bnb2", Coin("BNB", 25), "my memo")
    print(txn)

if __name__ == "__main__":
    main()
