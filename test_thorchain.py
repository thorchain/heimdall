import unittest

from thorchain import ThorchainState
from chains import Binance

from transaction import Transaction
from coin import Coin

class TestThorchainState(unittest.TestCase):

    def test_stake(self):
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain, 
            "STAKER-1", 
            "VAULT", 
            [Coin("BNB", 150000000), Coin("RUNE", 50000000000)], 
            "STAKE:BNB.BNB",
        )

        done = thorchain.handle(txn)
        self.assertEqual(done, True)

        pool = thorchain.get_pool("BNB.BNB")
        self.assertEqual(pool.rune_balance, 50000000000)
        self.assertEqual(pool.asset_balance, 150000000)


if __name__ == '__main__':
    unittest.main()
