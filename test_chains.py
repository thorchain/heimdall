import unittest

from chains import Account, Binance

from transaction import Transaction
from coin import Coin

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
        self.assertEqual(bnb._calculateGas(
            [Coin("BNB", 0)]
            ).equals(Coin("BNB", 37500)), 
            True,
        )
        self.assertEqual(bnb._calculateGas(
            [Coin("BNB", 0), Coin("RUNE", 0)]
            ).equals(Coin("BNB", 60000)), 
            True,
        )

    def test_seed(self):
        bnb = Binance()
        bnb.seed("tbnbA", Coin("BNB", 30))
        acct = bnb.get_account("tbnbA")
        self.assertEqual(acct.get("BNB"), 30)

    def test_transfer(self):
        bnb = Binance()
        bnb.seed("tbnbA", Coin("BNB", 300000000))
        txn = Transaction(bnb.chain, "tbnbA", "tbnbB", Coin("BNB", 200000000), "test transfer")
        bnb.transfer(txn)

        from_acct = bnb.get_account("tbnbA")
        to_acct = bnb.get_account("tbnbB")

        self.assertEqual(to_acct.get("BNB"), 200000000)
        self.assertEqual(from_acct.get("BNB"), 99962500)

if __name__ == '__main__':
    unittest.main()
