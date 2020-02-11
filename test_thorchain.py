import unittest

from thorchain import ThorchainState, Pool
from chains import Binance

from transaction import Transaction
from coin import Coin

class TestThorchainState(unittest.TestCase):

    def test_swap(self):
        # no pool, should emit a refund
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain, 
            "STAKER-1", 
            "VAULT", 
            [Coin("RUNE", 1000000000)], 
            "SWAP:BNB.BNB",
        )

        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND")

        # do a regular swap
        thorchain.pools = [Pool("BNB.BNB", 50*100000000,50*100000000)]
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "OUTBOUND:TODO")
        self.assertEqual(outbound[0].coins[0].asset, "BNB")
        self.assertEqual(outbound[0].coins[0].amount, 694444444)

        # swap with two coins on the inbound tx
        txn.coins = [[Coin("BNB", 1000000000)], Coin("RUNE-A1F", 1000000000)]
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)
        self.assertEqual(outbound[0].memo, "REFUND")

        # swap with zero return, refunds and doesn't change pools
        txn.coins = [Coin("RUNE-A1F", 1)]
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND")
        self.assertEqual(thorchain.pools[0].rune_balance, 60*100000000)

        # swap with limit
        txn.coins = [Coin("RUNE-A1F", 50)]
        txn.memo = "SWAP:BNB.BNB::999999999999999999999"
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND")
        self.assertEqual(thorchain.pools[0].rune_balance, 60*100000000)

        # swap with custom address
        txn.coins = [Coin("RUNE-A1F", 50)]
        txn.memo = "SWAP:BNB.BNB:NOMNOM:"
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "OUTBOUND:TODO")
        self.assertEqual(outbound[0].toAddress, "NOMNOM")

        # refund swap when address is a differnet network
        txn.coins = [Coin("RUNE-A1F", 50)]
        txn.memo = "SWAP:BNB.BNB:BNBNOMNOM"
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND")

        # do a double swap
        txn.coins = [Coin("BNB", 1000000)] 
        txn.memo = "SWAP:BNB.LOK-3C0"
        thorchain.pools.append(Pool("BNB.LOK-3C0", 30*100000000,30*100000000))
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "OUTBOUND:TODO")
        self.assertEqual(outbound[0].coins[0].asset, "LOK-3C0")
        self.assertEqual(outbound[0].coins[0].amount, 1391608)

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
