import unittest

from thorchain import ThorchainState
from chains import Binance

from transaction import Transaction
from coin import Coin

class TestThorchainState(unittest.TestCase):

    def test_add(self):
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain, 
            "STAKER-1", 
            "VAULT", 
            [Coin("BNB", 150000000), Coin("RUNE", 50000000000)], 
            "ADD:BNB.BNB",
        )

        outbound = thorchain.handle(txn)
        self.assertEqual(outbound, [])


    def test_stake(self):
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain, 
            "STAKER-1", 
            "VAULT", 
            [Coin("BNB", 150000000), Coin("RUNE", 50000000000)], 
            "STAKE:BNB.BNB",
        )

        outbound = thorchain.handle(txn)
        self.assertEqual(outbound, [])

        pool = thorchain.get_pool("BNB.BNB")
        self.assertEqual(pool.rune_balance, 50000000000)
        self.assertEqual(pool.asset_balance, 150000000)

        # should refund if no memo
        txn = Transaction(
            Binance.chain, 
            "STAKER-1", 
            "VAULT", 
            [Coin("BNB", 150000000), Coin("RUNE", 50000000000)], 
            "",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # bad stake memo should refund
        txn = Transaction(
            Binance.chain, 
            "STAKER-1", 
            "VAULT", 
            [Coin("BNB", 150000000), Coin("RUNE", 50000000000)], 
            "STAKE:",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # mismatch asset and memo
        txn = Transaction(
            Binance.chain, 
            "STAKER-1", 
            "VAULT", 
            [Coin("BNB", 150000000), Coin("RUNE", 50000000000)], 
            "STAKE:BNB.TCAN-014",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # cannot stake with rune in memo
        txn = Transaction(
            Binance.chain, 
            "STAKER-1", 
            "VAULT", 
            [Coin("BNB", 150000000), Coin("RUNE", 50000000000)], 
            "STAKE:RUNE-A1F",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # can stake with only asset
        txn = Transaction(
            Binance.chain, 
            "STAKER-1", 
            "VAULT", 
            [Coin("BNB", 30000000)], 
            "STAKE:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 0)
        txn = Transaction(
            Binance.chain, 
            "STAKER-1", 
            "VAULT", 
            [Coin("RUNE-A1F", 10000000000)], 
            "STAKE:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 0)

        txn = Transaction(
            Binance.chain, 
            "STAKER-1", 
            "VAULT", 
            [Coin("RUNE-A1F", 30000000000), Coin("BNB", 90000000)], 
            "STAKE:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 0)


if __name__ == '__main__':
    unittest.main()
