import unittest

from thorchain import ThorchainState, Pool, Event, RefundEvent
from chains import Binance

from common import Transaction, Coin


class TestThorchainState(unittest.TestCase):
    def test_swap(self):
        # no pool, should emit a refund
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("RUNE-A1F", 1000000000)],
            "SWAP:BNB.BNB",
        )

        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")

        # check refund event generated for swap with no pool
        events = thorchain.get_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "refund reason message: pool is zero")

        # do a regular swap
        thorchain.pools = [Pool("BNB.BNB", 50 * 100000000, 50 * 100000000)]
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "OUTBOUND:TODO")
        self.assertEqual(outbound[0].coins[0].asset, "BNB.BNB")
        self.assertEqual(outbound[0].coins[0].amount, 694444444)

        # check swap event generated for successful swap
        events = thorchain.get_events()
        self.assertEqual(len(events), 2)
        event = events[1]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "swap")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.pool, "BNB.BNB")
        self.assertEqual(event.event.price_target, 0)
        self.assertEqual(event.event.liquidity_fee, 138888888)
        self.assertEqual(event.event.trade_slip, 4400)

        # swap with two coins on the inbound tx
        txn.coins = [Coin("BNB", 1000000000), Coin("RUNE-A1F", 1000000000)]
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")

        # check refund event generated for swap with two coins
        events = thorchain.get_events()
        self.assertEqual(len(events), 3)
        event = events[2]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(
            event.event.reason,
            "invalid swap memo:not expecting multiple coins in a swap",
        )

        # swap with zero return, refunds and doesn't change pools
        txn.coins = [Coin("RUNE-A1F", 1)]
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")
        self.assertEqual(thorchain.pools[0].rune_balance, 60 * 100000000)

        # check refund event generated for swap with zero return
        events = thorchain.get_events()
        self.assertEqual(len(events), 4)
        event = events[3]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "emit asset 0 less than price limit 0")

        # swap with limit
        txn.coins = [Coin("RUNE-A1F", 50)]
        txn.memo = "SWAP:BNB.BNB::999999999999999999999"
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")
        self.assertEqual(thorchain.pools[0].rune_balance, 60 * 100000000)

        # check refund event generated for swap with limit
        events = thorchain.get_events()
        self.assertEqual(len(events), 5)
        event = events[4]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(
            event.event.reason,
            "emit asset 35 less than price limit 999999999999999999999",
        )

        # swap with custom address
        txn.coins = [Coin("RUNE-A1F", 50)]
        txn.memo = "SWAP:BNB.BNB:NOMNOM:"
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "OUTBOUND:TODO")
        self.assertEqual(outbound[0].to_address, "NOMNOM")

        # check swap event generated for successful swap
        events = thorchain.get_events()
        self.assertEqual(len(events), 6)
        event = events[5]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "swap")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.pool, "BNB.BNB")
        self.assertEqual(event.event.price_target, 0)
        self.assertEqual(event.event.liquidity_fee, 0)
        self.assertEqual(event.event.trade_slip, 0)

        # refund swap when address is a different network
        txn.coins = [Coin("RUNE-A1F", 50)]
        txn.memo = "SWAP:BNB.BNB:BNBNOMNOM"
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")

        # check refund event generated for swap with different network
        events = thorchain.get_events()
        self.assertEqual(len(events), 7)
        event = events[6]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "checksum failed. Expected ...")

        # do a double swap
        txn.coins = [Coin("BNB", 1000000)]
        txn.memo = "SWAP:BNB.LOK-3C0"
        thorchain.pools.append(Pool("BNB.LOK-3C0", 30 * 100000000, 30 * 100000000))
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "OUTBOUND:TODO")
        self.assertEqual(outbound[0].coins[0].asset, "BNB.LOK-3C0")
        self.assertEqual(outbound[0].coins[0].amount, 1391608)

        # check 2 swap events generated for double swap
        events = thorchain.get_events()
        self.assertEqual(len(events), 9)
        # first event of double swap
        self.maxDiff = None
        event = events[7]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "swap")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].memo, "SWAP:BNB.LOK-3C0")
        self.assertEqual(event.out_txs[0].coins[0].asset, "BNB.RUNE-A1F")
        self.assertEqual(event.out_txs[0].coins[0].amount, 1392901)
        self.assertEqual(event.out_txs[0].from_address, txn.from_address)
        self.assertEqual(event.out_txs[0].to_address, txn.to_address)
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.pool, "BNB.BNB")
        self.assertEqual(event.event.price_target, 0)
        self.assertEqual(event.event.liquidity_fee, 323)
        self.assertEqual(event.event.trade_slip, 4)
        # second event of double swap
        event = events[8]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "swap")
        self.assertEqual(event.in_tx.memo, "SWAP:BNB.LOK-3C0")
        self.assertEqual(event.in_tx.coins[0].asset, "BNB.RUNE-A1F")
        self.assertEqual(event.in_tx.coins[0].amount, 1392901)
        self.assertEqual(event.in_tx.from_address, txn.from_address)
        self.assertEqual(event.in_tx.to_address, txn.to_address)
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].memo, "OUTBOUND:TODO")
        self.assertEqual(event.out_txs[0].coins[0].asset, "BNB.LOK-3C0")
        self.assertEqual(event.out_txs[0].coins[0].amount, 1391608)
        self.assertEqual(event.out_txs[0].from_address, txn.to_address)
        self.assertEqual(event.out_txs[0].to_address, txn.from_address)
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.pool, "BNB.LOK-3C0")
        self.assertEqual(event.event.price_target, 0)
        self.assertEqual(event.event.liquidity_fee, 646)
        self.assertEqual(event.event.trade_slip, 9)

    def test_add(self):
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "ADD:BNB.BNB",
        )

        outbound = thorchain.handle(txn)
        self.assertEqual(outbound, [])

        # check event generated for successful add
        events = thorchain.get_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "add")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(event.out_txs, None)
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.pool, "BNB.BNB")

        # check add just rune
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("RUNE-A1F", 50000000000)],
            "ADD:RUNE-A1F",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 0)

        # check event generated for add with just rune
        events = thorchain.get_events()
        self.assertEqual(len(events), 2)
        event = events[1]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "add")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(event.out_txs, None)
        self.assertEqual(event.gas, None)
        # FIXME? do we have RUNE pool
        self.assertEqual(event.event.pool, "BNB.RUNE-A1F")

        # bad add memo should refund
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "ADD:",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # check refund event generated for add with bad memo
        events = thorchain.get_events()
        self.assertEqual(len(events), 3)
        event = events[2]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "Invalid symbol")

        # mismatch asset and memo
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "ADD:BNB.TCAN-014",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # check refund event generated for add with mismatch asset and memo
        events = thorchain.get_events()
        self.assertEqual(len(events), 4)
        event = events[3]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "Invalid symbol")

        # cannot add with rune in memo
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "ADD:RUNE-A1F",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # check refund event generated for add with rune in memo
        events = thorchain.get_events()
        self.assertEqual(len(events), 5)
        event = events[4]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "Invalid symbol")

        # cannot add with > 2 coins
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [
                Coin("BNB", 150000000),
                Coin("RUNE-A1F", 50000000000),
                Coin("BNB-LOK-3C0", 30000000000),
            ],
            "ADD:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 3)

        # check refund event generated for add with > 2 coins
        events = thorchain.get_events()
        self.assertEqual(len(events), 6)
        event = events[5]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.out_txs[2].to_json(), outbound[2].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "refund reason message")  # FIXME

    def test_reserve(self):
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("RUNE-A1F", 50000000000)],
            "RESERVE",
        )

        outbound = thorchain.handle(txn)
        self.assertEqual(outbound, [])

        self.assertEqual(thorchain.reserve, 50000000000)

        # check event generated for successful reserve
        events = thorchain.get_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "reserve")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(event.out_txs, None)
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.reserve_contributor["address"], txn.from_address)
        self.assertEqual(event.event.reserve_contributor["amount"], txn.coins[0].amount)

    def test_gas(self):
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "STAKE:BNB.BNB",
        )

        outbound = thorchain.handle(txn)
        self.assertEqual(outbound, [])

        pool = thorchain.get_pool("BNB.BNB")
        self.assertEqual(pool.rune_balance, 50000000000)
        self.assertEqual(pool.asset_balance, 150000000)
        self.assertEqual(pool.get_staker("STAKER-1").units, 25075000000)
        self.assertEqual(pool.total_units, 25075000000)

        # check event generated for successful stake
        events = thorchain.get_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "stake")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(event.out_txs[0].to_json(), Transaction.empty_txn().to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.pool, pool.asset)
        self.assertEqual(event.event.stake_units, pool.total_units)

        # should refund if no memo
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # check refund event generated for stake with no memo
        events = thorchain.get_events()
        self.assertEqual(len(events), 2)
        event = events[1]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "memo can't be empty")

        # check gas event generated after we sent to chain
        outbound[0].gas = [Coin("BNB", 37500)]
        outbound[1].gas = [Coin("BNB", 37500)]
        thorchain.handle_gas(outbound)

        events = thorchain.get_events()
        self.assertEqual(len(events), 4)
        # first new gas event
        event = events[2]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "gas")
        self.assertEqual(event.in_tx.to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs, None)
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.gas[0].is_equal(outbound[0].gas[0]), True)
        self.assertEqual(event.event.gas_type, "gas_spend")

        # second new gas event
        event = events[3]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "gas")
        self.assertEqual(event.in_tx.to_json(), outbound[1].to_json())
        self.assertEqual(event.out_txs, None)
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.gas[0].is_equal(outbound[1].gas[0]), True)
        self.assertEqual(event.event.gas_type, "gas_spend")

    def test_stake(self):
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "STAKE:BNB.BNB",
        )

        outbound = thorchain.handle(txn)
        self.assertEqual(outbound, [])

        pool = thorchain.get_pool("BNB.BNB")
        self.assertEqual(pool.rune_balance, 50000000000)
        self.assertEqual(pool.asset_balance, 150000000)
        self.assertEqual(pool.get_staker("STAKER-1").units, 25075000000)
        self.assertEqual(pool.total_units, 25075000000)

        # check event generated for successful stake
        events = thorchain.get_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "stake")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(event.out_txs[0].to_json(), Transaction.empty_txn().to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.pool, pool.asset)
        self.assertEqual(event.event.stake_units, pool.total_units)

        # should refund if no memo
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # check refund event generated for stake with no memo
        events = thorchain.get_events()
        self.assertEqual(len(events), 2)
        event = events[1]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "memo can't be empty")

        # bad stake memo should refund
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "STAKE:",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # check refund event generated for stake with bad memo
        events = thorchain.get_events()
        self.assertEqual(len(events), 3)
        event = events[2]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "Invalid symbol")

        # mismatch asset and memo
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "STAKE:BNB.TCAN-014",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # check refund event generated for stake with mismatch asset and memo
        events = thorchain.get_events()
        self.assertEqual(len(events), 4)
        event = events[3]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(
            event.event.reason, "invalid stake memo: did not find BNB.TCAN-014"
        )

        # cannot stake with rune in memo
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "STAKE:RUNE-A1F",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # check refund event generated for stake with rune in memo
        events = thorchain.get_events()
        self.assertEqual(len(events), 5)
        event = events[4]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "invalid stake memo:invalid pool asset")

        # cannot stake with > 2 coins
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [
                Coin("BNB", 150000000),
                Coin("RUNE-A1F", 50000000000),
                Coin("BNB-LOK-3C0", 30000000000),
            ],
            "STAKE:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 3)

        # check refund event generated for stake with > 2 coins
        events = thorchain.get_events()
        self.assertEqual(len(events), 6)
        event = events[5]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.out_txs[2].to_json(), outbound[2].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "refund reason message")  # FIXME

        # can stake with only asset
        txn = Transaction(
            Binance.chain,
            "STAKER-2",
            "VAULT",
            [Coin("BNB", 30000000)],
            "STAKE:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 0)
        self.assertEqual(pool.get_staker("STAKER-2").units, 2090833333)
        self.assertEqual(pool.total_units, 27165833333)

        # check event generated for successful stake
        events = thorchain.get_events()
        self.assertEqual(len(events), 7)
        event = events[6]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "stake")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(event.out_txs[0].to_json(), Transaction.empty_txn().to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.pool, pool.asset)
        self.assertEqual(event.event.stake_units, pool.total_units)

        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("RUNE-A1F", 10000000000)],
            "STAKE:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 0)

        # check event generated for successful stake
        events = thorchain.get_events()
        self.assertEqual(len(events), 8)
        event = events[7]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "stake")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(event.out_txs[0].to_json(), Transaction.empty_txn().to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.pool, pool.asset)
        self.assertEqual(event.event.stake_units, pool.total_units)

        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("RUNE-A1F", 30000000000), Coin("BNB", 90000000)],
            "STAKE:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 0)

        # check event generated for successful stake
        events = thorchain.get_events()
        self.assertEqual(len(events), 9)
        event = events[8]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "stake")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(event.out_txs[0].to_json(), Transaction.empty_txn().to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.pool, pool.asset)
        self.assertEqual(event.event.stake_units, pool.total_units)

    def test_unstake(self):
        thorchain = ThorchainState()
        # stake some funds into a pool
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "STAKE:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(outbound, [])

        pool = thorchain.get_pool("BNB.BNB")
        self.assertEqual(pool.rune_balance, 50000000000)
        self.assertEqual(pool.asset_balance, 150000000)
        self.assertEqual(pool.get_staker("STAKER-1").units, 25075000000)
        self.assertEqual(pool.total_units, 25075000000)

        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("RUNE-A1F", 1)],
            "WITHDRAW:BNB.BNB:100",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)
        self.assertEqual(outbound[0].coins[0].asset, "BNB.RUNE-A1F")
        self.assertEqual(outbound[0].coins[0].amount, 500000000)
        self.assertEqual(outbound[1].coins[0].asset, "BNB.BNB")
        self.assertEqual(outbound[1].coins[0].amount, 1500000)

        pool = thorchain.get_pool("BNB.BNB")
        self.assertEqual(pool.rune_balance, 49500000000)
        self.assertEqual(pool.asset_balance, 148500000)
        self.assertEqual(pool.get_staker("STAKER-1").units, 24824250000)
        self.assertEqual(pool.total_units, 24824250000)

        # check event generated for successful unstake
        events = thorchain.get_events()
        self.assertEqual(len(events), 2)  # stake + unstake events
        event = events[1]  # checking unstake event, last event
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "unstake")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.pool, "BNB.BNB")
        self.assertEqual(event.event.stake_units, pool.total_units)
        self.assertEqual(event.event.basis_points, 100)
        self.assertEqual(event.event.asymmetry, 0)

        # should error without a pool referenced
        txn.memo = "WITHDRAW:"
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")

        # check refund event generated for unstake with bad memo
        events = thorchain.get_events()
        self.assertEqual(len(events), 3)
        event = events[2]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "Invalid symbol")

        # should error without a bad withdraw basis points, should be between 0
        # and 10,000
        txn.memo = "WITHDRAW::-4"
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")

        # check refund event generated for unstake with bad withdraw basis points
        events = thorchain.get_events()
        self.assertEqual(len(events), 4)
        event = events[3]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "Invalid symbol")

        txn.memo = "WITHDRAW::1000000000"
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")

        # check refund event generated for unstake with bad memo
        events = thorchain.get_events()
        self.assertEqual(len(events), 5)
        event = events[4]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "Invalid symbol")

        # check successful withdraw everything
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("RUNE-A1F", 1)],
            "WITHDRAW:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)
        self.assertEqual(outbound[0].coins[0].asset, "BNB.RUNE-A1F")
        self.assertEqual(outbound[0].coins[0].amount, 49500000000)
        self.assertEqual(outbound[1].coins[0].asset, "BNB.BNB")
        self.assertEqual(outbound[1].coins[0].amount, 148500000)

        pool = thorchain.get_pool("BNB.BNB")
        self.assertEqual(pool.rune_balance, 0)
        self.assertEqual(pool.asset_balance, 0)
        self.assertEqual(pool.get_staker("STAKER-1").units, 0)
        self.assertEqual(pool.total_units, 0)

        # check event generated for successful unstake
        events = thorchain.get_events()
        self.assertEqual(len(events), 6)
        event = events[5]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "unstake")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.pool, "BNB.BNB")
        self.assertEqual(event.event.stake_units, pool.total_units)
        self.assertEqual(event.event.basis_points, 10000)
        self.assertEqual(event.event.asymmetry, 0)

        # check withdraw staker has 0 units
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("RUNE-A1F", 1)],
            "WITHDRAW:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].coins[0].asset, "BNB.RUNE-A1F")
        self.assertEqual(outbound[0].coins[0].amount, 1)

        pool = thorchain.get_pool("BNB.BNB")
        self.assertEqual(pool.rune_balance, 0)
        self.assertEqual(pool.asset_balance, 0)
        self.assertEqual(pool.get_staker("STAKER-1").units, 0)
        self.assertEqual(pool.total_units, 0)

        # check refund event generated for unstake with 0 units left
        events = thorchain.get_events()
        self.assertEqual(len(events), 7)
        event = events[6]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "refund reason message")

    def test_unstake_calc(self):
        pool = Pool("BNB.BNB", 112928660551, 257196272)
        pool.total_units = 44611997190
        after, withdraw_rune, withdraw_asset = pool._calc_unstake_units(
            25075000000, 5000
        )
        self.assertEqual(withdraw_rune, 31736823519)
        self.assertEqual(withdraw_asset, 72280966)
        self.assertEqual(after, 12537500000)

    def test_stake_calc(self):
        pool = Pool("BNB.BNB", 112928660551, 257196272)
        stake_units = pool._calc_stake_units(
            50000000000, 50000000000, 34500000000, 23400000000
        )
        self.assertEqual(stake_units, 28950000000)
        stake_units = pool._calc_stake_units(
            50000000000, 40000000000, 50000000000, 40000000000
        )
        self.assertEqual(stake_units, 45000000000)

    def test_calc_liquidity_fee(self):
        thorchain = ThorchainState()
        fee = thorchain._calc_liquidity_fee(94382619747, 100001000, 301902607)
        self.assertEqual(fee, 338)
        fee = thorchain._calc_liquidity_fee(10000000000, 1000000000, 10000000000)
        self.assertEqual(fee, 82644628)

    def test_calc_trade_slip(self):
        thorchain = ThorchainState()
        slip = thorchain._calc_trade_slip(10000000000, 1000000000)
        self.assertEqual(slip, 2100)

    def test_get_asset_in_rune(self):
        pool = Pool("BNB.BNB", 49900000000, 150225000)
        self.assertEqual(pool.get_asset_in_rune(75000), 24912631)

        pool = Pool("BNB.BNB", 49824912631, 150450902)
        self.assertEqual(pool.get_asset_in_rune(75000), 24837794)

    def test_get_asset_fee(self):
        pool = Pool("BNB.BNB", 49900000000, 150225000)
        self.assertEqual(pool.get_asset_fee(), 301052)

    def test_handle_rewards(self):
        thorchain = ThorchainState()
        thorchain.pools.append(Pool("BNB.BNB", 94382620747, 301902605))
        thorchain.pools.append(Pool("BNB.LOKI", 50000000000, 100))
        thorchain.reserve = 40001517380253

        # test minus rune from pools and add to bond rewards (too much rewards to pools)
        thorchain.liquidity["BNB.BNB"] = 105668
        thorchain.handle_rewards()
        self.assertEqual(thorchain.pools[0].rune_balance, 94382515079)

        # test no swaps this block (no rewards)
        thorchain.handle_rewards()
        self.assertEqual(thorchain.pools[0].rune_balance, 94382515079)

        # test add rune to pools (not enough funds to pools)
        thorchain.liquidity["BNB.LOKI"] = 103
        thorchain.total_bonded = 5000000000000
        thorchain.handle_rewards()
        self.assertEqual(thorchain.pools[1].rune_balance, 50000997031)

    def test_get_events(self):
        thorchain = ThorchainState()
        # get first id for next generated event
        events_first_id = next(Event.id_iter) + 1

        # stake some funds into a pool
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "STAKE:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 0)

        # stake some funds into a pool
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.LOK-3C0", 150000000), Coin("RUNE-A1F", 50000000000)],
            "STAKE:BNB.LOK-3C0",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 0)

        # unstake
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("RUNE-A1F", 1)],
            "WITHDRAW:BNB.BNB:100",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # check get_event generated for for all actions
        events = thorchain.get_events()
        self.assertEqual(len(events), 3)  # 2 stake + 1 unstake events
        # check auto count id
        self.assertEqual(events[0].id, events_first_id)
        self.assertEqual(events[1].id, events[0].id + 1)
        self.assertEqual(events[2].id, events[1].id + 1)

        #  check type events ordered correctly
        self.assertEqual(events[0].type, "stake")
        self.assertEqual(events[1].type, "stake")
        self.assertEqual(events[2].type, "unstake")

        # check get_event from a specific id
        # default id 1 should return the same
        events = thorchain.get_events(events_first_id)
        self.assertEqual(len(events), 3)  # 2 stake + 1 unstake events

        # check get_event from a specific id
        events = thorchain.get_events(events_first_id + 1)
        self.assertEqual(len(events), 2)  # 1 stake + 1 unstake events
        self.assertEqual(events[0].type, "stake")
        self.assertEqual(events[1].type, "unstake")

        # check get_event from a specific id
        events = thorchain.get_events(events_first_id + 2)
        self.assertEqual(len(events), 1)  # 1 unstake
        self.assertEqual(events[0].type, "unstake")


class TestEvent(unittest.TestCase):
    def test_str(self):
        refund_event = RefundEvent(105, "memo can't be empty")
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("RUNE-A1F", 50000000000)],
            "ADD:RUNE-A1F",
        )
        event = Event("refund", txn, None, refund_event)
        event.id = 1
        self.assertEqual(
            str(event),
            """
Event #1 | Type REFUND | Status Success |
InTx  Transaction STAKER-1 ==> VAULT | 50,000,000,000BNB.RUNE-A1F | ADD:RUNE-A1F
OutTx None
Event RefundEvent Code 105 | Reason memo can't be empty
            """,
        )

    def test_repr(self):
        refund_event = RefundEvent(105, "memo can't be empty")
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("RUNE-A1F", 50000000000)],
            "ADD:RUNE-A1F",
        )
        event = Event("refund", txn, None, refund_event, status="Refund")
        event.id = 1
        self.assertEqual(
            repr(event),
            """
Event #1 | Type REFUND | Status Refund |
InTx  Transaction STAKER-1 ==> VAULT | 50,000,000,000BNB.RUNE-A1F | ADD:RUNE-A1F
OutTx None
Event RefundEvent Code 105 | Reason memo can't be empty
            """,
        )

    def test_to_json(self):
        refund_event = RefundEvent(105, "memo can't be empty")
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("RUNE-A1F", 50000000000)],
            "ADD:RUNE-A1F",
        )
        event = Event("refund", txn, None, refund_event)
        event.id = 1
        self.assertEqual(
            event.to_json(),
            '{"id": 1, "type": "refund", "in_tx": {"chain": "BNB", "from_address": "STAKER-1", "to_address": "VAULT", "memo": "ADD:RUNE-A1F", "coins": [{"asset": "BNB.RUNE-A1F", "amount": 50000000000}], "gas": null}, "out_txs": null, "gas": null, "event": {"code": 105, "reason": "memo can\'t be empty"}, "status": "Success"}',
        )

    def test_from_dict(self):
        value = {
            "id": 1,
            "type": "refund",
            "in_tx": {
                "chain": "BNB",
                "from_address": "STAKER-1",
                "to_address": "VAULT",
                "memo": "ADD:RUNE-A1F",
                "coins": [{"asset": "BNB.RUNE-A1F", "amount": 50000000000}],
                "gas": None,
            },
            "out_txs": None,
            "gas": None,
            "event": {"code": 105, "reason": "memo can't be empty"},
            "status": "Success",
        }
        event = Event.from_dict(value)
        self.assertEqual(event.id, 1)
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.chain, "BNB")
        self.assertEqual(event.in_tx.from_address, "STAKER-1")
        self.assertEqual(event.in_tx.to_address, "VAULT")
        self.assertEqual(event.in_tx.memo, "ADD:RUNE-A1F")
        self.assertEqual(event.in_tx.coins[0].asset, "BNB.RUNE-A1F")
        self.assertEqual(event.in_tx.coins[0].amount, 50000000000)
        self.assertEqual(event.out_txs, None)
        self.assertEqual(event.gas, None)
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "memo can't be empty")

        value = {
            "id": 1,
            "type": "refund",
            "in_tx": {
                "chain": "BNB",
                "from_address": "STAKER-1",
                "to_address": "VAULT",
                "memo": "",
                "coins": [
                    {"asset": "BNB.RUNE-A1F", "amount": 50000000000},
                    {"asset": "BNB.BNB", "amount": 30000000000},
                ],
                "gas": [{"asset": "BNB.BNB", "amount": 60000}],
            },
            "out_txs": [
                {
                    "chain": "BNB",
                    "from_address": "VAULT",
                    "to_address": "STAKER-1",
                    "memo": "REFUND:TODO",
                    "coins": [{"asset": "BNB.RUNE-A1F", "amount": 50000000000}],
                    "gas": [{"asset": "BNB.BNB", "amount": 35000}],
                },
                {
                    "chain": "BNB",
                    "from_address": "VAULT",
                    "to_address": "STAKER-1",
                    "memo": "REFUND:TODO",
                    "coins": [{"asset": "BNB.BNB", "amount": 30000000000}],
                    "gas": [{"asset": "BNB.BNB", "amount": 35000}],
                },
            ],
            "gas": None,
            "event": {"code": "105", "reason": "memo can't be empty",},
            "status": "Refund",
        }
        event = Event.from_dict(value)
        self.assertEqual(event.id, 1)
        self.assertEqual(event.type, "refund")
        # in_tx
        self.assertEqual(event.in_tx.chain, "BNB")
        self.assertEqual(event.in_tx.from_address, "STAKER-1")
        self.assertEqual(event.in_tx.to_address, "VAULT")
        self.assertEqual(event.in_tx.memo, "")
        self.assertEqual(event.in_tx.coins[0].asset, "BNB.RUNE-A1F")
        self.assertEqual(event.in_tx.coins[0].amount, 50000000000)
        self.assertEqual(event.in_tx.coins[1].asset, "BNB.BNB")
        self.assertEqual(event.in_tx.coins[1].amount, 30000000000)
        self.assertEqual(event.in_tx.gas[0].asset, "BNB.BNB")
        self.assertEqual(event.in_tx.gas[0].amount, 60000)
        # out_tx 1
        self.assertEqual(event.out_txs[0].chain, "BNB")
        self.assertEqual(event.out_txs[0].from_address, "VAULT")
        self.assertEqual(event.out_txs[0].to_address, "STAKER-1")
        self.assertEqual(event.out_txs[0].memo, "REFUND:TODO")
        self.assertEqual(event.out_txs[0].coins[0].asset, "BNB.RUNE-A1F")
        self.assertEqual(event.out_txs[0].coins[0].amount, 50000000000)
        self.assertEqual(event.out_txs[0].gas[0].asset, "BNB.BNB")
        self.assertEqual(event.out_txs[0].gas[0].amount, 35000)
        # out_tx 2
        self.assertEqual(event.out_txs[1].chain, "BNB")
        self.assertEqual(event.out_txs[1].from_address, "VAULT")
        self.assertEqual(event.out_txs[1].to_address, "STAKER-1")
        self.assertEqual(event.out_txs[1].memo, "REFUND:TODO")
        self.assertEqual(event.out_txs[1].coins[0].asset, "BNB.BNB")
        self.assertEqual(event.out_txs[1].coins[0].amount, 30000000000)
        self.assertEqual(event.out_txs[1].gas[0].asset, "BNB.BNB")
        self.assertEqual(event.out_txs[1].gas[0].amount, 35000)

        self.assertEqual(event.gas, None)

        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "memo can't be empty")


if __name__ == "__main__":
    unittest.main()
