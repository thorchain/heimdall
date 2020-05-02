import unittest

from chains.account import Account
from chains.binance import Binance

from utils.common import Transaction, Coin


class TestAccount(unittest.TestCase):
    def test_addsub(self):
        acct = Account("tbnbA")
        acct.add(Coin("BNB", 25))
        self.assertEqual(acct.get("BNB"), 25)
        acct.add([Coin("BNB", 20), Coin("RUNE", 100)])
        self.assertEqual(acct.get("BNB"), 45)
        self.assertEqual(acct.get("RUNE"), 100)

        acct.sub([Coin("BNB", 20), Coin("RUNE", 100)])
        self.assertEqual(acct.get("BNB"), 25)
        self.assertEqual(acct.get("RUNE"), 0)


class TestBinance(unittest.TestCase):
    def test_gas(self):
        bnb = Binance()
        self.assertEqual(
            bnb._calculate_gas([Coin("BNB", 5757575)]), Coin("BNB", 37500),
        )
        self.assertEqual(
            bnb._calculate_gas([Coin("BNB", 0), Coin("RUNE", 0)]), Coin("BNB", 60000)
        )

    def test_transfer(self):
        bnb = Binance()
        from_acct = bnb.get_account("tbnbA")
        from_acct.add(Coin("BNB", 300000000))
        bnb.set_account(from_acct)

        txn = Transaction(
            bnb.chain, "tbnbA", "tbnbB", Coin("BNB", 200000000), "test transfer"
        )
        bnb.transfer(txn)

        to_acct = bnb.get_account("tbnbB")

        self.assertEqual(to_acct.get("BNB"), 200000000)
        self.assertEqual(from_acct.get("BNB"), 99962500)


if __name__ == "__main__":
    unittest.main()
