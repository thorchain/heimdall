import unittest
import logging

from thorchain.thorchain import (
    ThorchainClient,
    ThorchainState,
    Pool,
    Event,
)
from chains.binance import Binance

from utils.common import Transaction, Coin, get_rune_asset

RUNE = get_rune_asset()


class TestThorchainState(unittest.TestCase):
    def test_swap(self):
        # no pool, should emit a refund
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin(RUNE, 1000000000)],
            "SWAP:BNB.BNB",
        )

        outbound = thorchain.handle(txn)
        outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")

        # check refund event generated for swap with no pool
        events = thorchain.events
        logging.info(events)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.fee.coins, [Coin(RUNE, 100000000)])
        self.assertEqual(event.fee.pool_deduct, 0)
        self.assertEqual(event.event.reason, "refund reason message: pool is zero")

        # do a regular swap
        thorchain.pools = [Pool("BNB.BNB", 50 * 100000000, 50 * 100000000)]
        outbound = thorchain.handle(txn)
        outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "OUTBOUND:TODO")
        self.assertEqual(outbound[0].coins[0].asset, "BNB.BNB")
        self.assertEqual(outbound[0].coins[0].amount, 622685185)

        # check swap event generated for successful swap
        events = thorchain.get_events()
        self.assertEqual(len(events), 2)
        event = events[1]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "swap")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.event.pool, "BNB.BNB")
        self.assertEqual(event.event.price_target, 0)
        self.assertEqual(event.event.liquidity_fee, 138888888)
        self.assertEqual(event.event.liquidity_fee_in_rune, 138888888)
        self.assertEqual(event.event.trade_slip, 4400)
        self.assertEqual(event.fee.coins, [Coin("BNB.BNB", 71759259)])
        self.assertEqual(event.fee.pool_deduct, 100000000)

        # swap with two coins on the inbound tx
        txn.coins = [Coin("BNB.BNB", 1000000000), Coin(RUNE, 1000000000)]
        outbound = thorchain.handle(txn)
        outbound = thorchain.handle_fee(txn, outbound)
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
        self.assertEqual(event.event.code, 105)
        self.assertEqual(
            event.event.reason,
            "invalid swap memo:not expecting multiple coins in a swap",
        )
        self.assertEqual(
            event.fee.coins, [Coin("BNB.BNB", 74191777), Coin(RUNE, 100000000)]
        )
        self.assertEqual(event.fee.pool_deduct, 100000000)

        # swap with zero return, refunds and doesn't change pools
        txn.coins = [Coin(RUNE, 1)]
        outbound = thorchain.handle(txn)
        # outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")
        self.assertEqual(thorchain.pools[0].rune_balance, 58 * 100000000)

        # check refund event generated for swap with zero return
        events = thorchain.get_events()
        self.assertEqual(len(events), 4)
        event = events[3]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.event.code, 108)
        self.assertEqual(event.event.reason, "emit asset 0 less than price limit 0")
        self.assertEqual(event.fee.coins, None)
        self.assertEqual(event.fee.pool_deduct, 0)

        # swap with zero return, not enough coin to pay fee so no refund
        txn.coins = [Coin(RUNE, 1)]
        outbound = thorchain.handle(txn)
        outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 0)
        self.assertEqual(thorchain.pools[0].rune_balance, 58 * 100000000)

        # check refund event generated for swap with zero return
        events = thorchain.get_events()
        self.assertEqual(len(events), 5)
        event = events[4]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.event.code, 108)
        self.assertEqual(event.event.reason, "emit asset 0 less than price limit 0")
        self.assertEqual(event.fee.coins, [Coin(RUNE, 100000000)])
        self.assertEqual(event.fee.pool_deduct, 0)

        # swap with limit
        txn.coins = [Coin(RUNE, 500000000)]
        txn.memo = "SWAP:BNB.BNB::999999999999999999999"
        outbound = thorchain.handle(txn)
        outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")
        self.assertEqual(outbound[0].coins, [Coin(RUNE, 400000000)])
        self.assertEqual(thorchain.pools[0].rune_balance, 58 * 100000000)

        # check refund event generated for swap with limit
        events = thorchain.get_events()
        self.assertEqual(len(events), 6)
        event = events[5]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.event.code, 108)
        self.assertEqual(
            event.event.reason,
            "emit asset 325254953 less than price limit 999999999999999999999",
        )
        self.assertEqual(event.fee.coins, [Coin(RUNE, 100000000)])
        self.assertEqual(event.fee.pool_deduct, 0)

        # swap with custom address
        txn.coins = [Coin(RUNE, 500000000)]
        txn.memo = "SWAP:BNB.BNB:NOMNOM:"
        outbound = thorchain.handle(txn)
        outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "OUTBOUND:TODO")
        self.assertEqual(outbound[0].to_address, "NOMNOM")

        # check swap event generated for successful swap
        events = thorchain.get_events()
        self.assertEqual(len(events), 7)
        event = events[6]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "swap")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.event.pool, "BNB.BNB")
        self.assertEqual(event.event.price_target, 0)
        self.assertEqual(event.event.liquidity_fee_in_rune, 36533132)
        self.assertEqual(event.event.liquidity_fee, 28039220)
        self.assertEqual(event.event.trade_slip, 1798)
        self.assertEqual(event.fee.coins, [Coin("BNB.BNB", 65496058)])
        self.assertEqual(event.fee.pool_deduct, 100000000)

        # refund swap when address is a different network
        txn.coins = [Coin(RUNE, 500000000)]
        txn.memo = "SWAP:BNB.BNB:BNBNOMNOM"
        outbound = thorchain.handle(txn)
        outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")

        # check refund event generated for swap with different network
        events = thorchain.get_events()
        self.assertEqual(len(events), 8)
        event = events[7]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "address format not supported: BNBNOMNOM")
        self.assertEqual(event.fee.coins, [Coin(RUNE, 100000000)])
        self.assertEqual(event.fee.pool_deduct, 0)

        # do a double swap
        txn.coins = [Coin("BNB.BNB", 1000000000)]
        txn.memo = "SWAP:BNB.LOK-3C0"
        thorchain.pools.append(Pool("BNB.LOK-3C0", 30 * 100000000, 30 * 100000000))
        outbound = thorchain.handle(txn)
        outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "OUTBOUND:TODO")
        self.assertEqual(outbound[0].coins[0].asset, "BNB.LOK-3C0")
        self.assertEqual(outbound[0].coins[0].amount, 490449869)

        # check 2 swap events generated for double swap
        events = thorchain.get_events()
        self.assertEqual(len(events), 10)
        # first event of double swap
        self.maxDiff = None
        event = events[8]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "swap")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].memo, "SWAP:BNB.LOK-3C0")
        self.assertEqual(event.out_txs[0].coins[0].asset, RUNE)
        self.assertEqual(event.out_txs[0].coins[0].amount, 964183435)
        self.assertEqual(event.out_txs[0].from_address, txn.from_address)
        self.assertEqual(event.out_txs[0].to_address, txn.to_address)
        self.assertEqual(event.event.pool, "BNB.BNB")
        self.assertEqual(event.event.price_target, 0)
        self.assertEqual(event.event.liquidity_fee, 230019434)
        self.assertEqual(event.event.liquidity_fee_in_rune, 230019434)
        self.assertEqual(event.event.trade_slip, 5340)
        self.assertEqual(event.fee.coins, None)
        self.assertEqual(event.fee.pool_deduct, 0)
        # second event of double swap
        event = events[9]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "swap")
        self.assertEqual(event.in_tx.memo, "SWAP:BNB.LOK-3C0")
        self.assertEqual(event.in_tx.coins[0].asset, RUNE)
        self.assertEqual(event.in_tx.coins[0].amount, 964183435)
        self.assertEqual(event.in_tx.from_address, txn.from_address)
        self.assertEqual(event.in_tx.to_address, txn.to_address)
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].memo, "OUTBOUND:TODO")
        self.assertEqual(event.out_txs[0].coins[0].asset, "BNB.LOK-3C0")
        self.assertEqual(event.out_txs[0].coins[0].amount, 490449869)
        self.assertEqual(event.out_txs[0].from_address, txn.to_address)
        self.assertEqual(event.out_txs[0].to_address, txn.from_address)
        self.assertEqual(event.event.pool, "BNB.LOK-3C0")
        self.assertEqual(event.event.price_target, 0)
        self.assertEqual(event.event.liquidity_fee, 177473331)
        self.assertEqual(event.event.liquidity_fee_in_rune, 177473331)
        self.assertEqual(event.event.trade_slip, 7461)
        self.assertEqual(event.fee.coins, [Coin("BNB.LOK-3C0", 61747954)])
        self.assertEqual(event.fee.pool_deduct, 100000000)

    def test_fee(self):
        thorchain = ThorchainState()
        thorchain.pools = [Pool("BNB.BNB", 50 * 100000000, 50 * 100000000)]

        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 1000000000), Coin(RUNE, 1000000000)],
            "SWAP:BNB.BNB",
        )

        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")
        self.assertEqual(outbound[0].coins[0], Coin("BNB.BNB", 1000000000))
        self.assertEqual(outbound[1].memo, "REFUND:TODO")
        self.assertEqual(outbound[1].coins[0], Coin(RUNE, 1000000000))

        # check refund event generated for swap with two coins
        events = thorchain.get_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.event.code, 105)
        self.assertEqual(
            event.event.reason,
            "invalid swap memo:not expecting multiple coins in a swap",
        )

        outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 2)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")
        self.assertEqual(outbound[0].coins[0], Coin("BNB.BNB", 900000000))
        self.assertEqual(outbound[1].memo, "REFUND:TODO")
        self.assertEqual(outbound[1].coins[0], Coin(RUNE, 900000000))

        # check refund event generated for swap with two coins
        events = thorchain.get_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.event.code, 105)
        self.assertEqual(
            event.event.reason,
            "invalid swap memo:not expecting multiple coins in a swap",
        )

        # make RUNE coin same amount as fee, we should
        # then only get 1 txn outbound after fee
        txn.coins = [Coin("BNB.BNB", 1000000000), Coin(RUNE, 100000000)]

        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")
        self.assertEqual(outbound[0].coins[0], Coin("BNB.BNB", 1000000000))
        self.assertEqual(outbound[1].memo, "REFUND:TODO")
        self.assertEqual(outbound[1].coins[0], Coin(RUNE, 100000000))

        # check refund event generated for swap with two coins
        events = thorchain.get_events()
        self.assertEqual(len(events), 2)
        event = events[1]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.event.code, 105)
        self.assertEqual(
            event.event.reason,
            "invalid swap memo:not expecting multiple coins in a swap",
        )

        outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")
        self.assertEqual(outbound[0].coins[0], Coin("BNB.BNB", 895918367))

        # check refund event generated for swap with two coins
        events = thorchain.get_events()
        self.assertEqual(len(events), 2)
        event = events[1]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.event.code, 105)
        self.assertEqual(
            event.event.reason,
            "invalid swap memo:not expecting multiple coins in a swap",
        )

    def test_add(self):
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
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
        self.assertEqual(event.out_txs, [])
        self.assertEqual(event.event.pool, "BNB.BNB")

        # check add just rune
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin(RUNE, 50000000000)],
            "ADD:" + RUNE,
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
        self.assertEqual(event.out_txs, [])
        # FIXME? do we have RUNE pool
        self.assertEqual(event.event.pool, RUNE)

        # bad add memo should refund
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
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
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "Invalid symbol")

        # mismatch asset and memo
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
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
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "Invalid symbol")

        # cannot add with rune in memo
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
            "ADD:" + RUNE,
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
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "Invalid symbol")

        # cannot add with > 2 coins
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [
                Coin("BNB.BNB", 150000000),
                Coin(RUNE, 50000000000),
                Coin("BNB-LOK-3C0", 30000000000),
            ],
            "ADD:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

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
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "refund reason message")  # FIXME

    def test_reserve(self):
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain, "STAKER-1", "VAULT", [Coin(RUNE, 50000000000)], "RESERVE",
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
        self.assertEqual(event.out_txs, [])
        self.assertEqual(event.event.reserve_contributor["address"], txn.from_address)
        self.assertEqual(event.event.reserve_contributor["amount"], txn.coins[0].amount)

    def test_gas(self):
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
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
        self.assertEqual(event.event.pool, pool.asset)
        self.assertEqual(event.event.stake_units, pool.total_units)

        # should refund if no memo
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
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
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "memo can't be empty")

        # check gas event generated after we sent to chain
        outbound[0].gas = [Coin("BNB.BNB", 37500)]
        outbound[1].gas = [Coin("BNB.BNB", 37500)]
        thorchain.handle_gas(outbound)

        events = thorchain.get_events()
        self.assertEqual(len(events), 3)
        # first new gas event
        event = events[2]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "gas")
        self.assertEqual(event.in_tx.to_json(), Transaction.empty_txn().to_json())
        self.assertEqual(event.out_txs, [])
        self.assertEqual(event.event.pools, [EventGasPool("BNB.BNB", 75000, 25000000)])

    def test_stake(self):
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
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
        self.assertEqual(event.event.pool, pool.asset)
        self.assertEqual(event.event.stake_units, pool.total_units)

        # should refund if no memo
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
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
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "memo can't be empty")

        # bad stake memo should refund
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
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
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "Invalid symbol")

        # mismatch asset and memo
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
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
        self.assertEqual(event.event.code, 105)
        self.assertEqual(
            event.event.reason, "invalid stake memo:did not find BNB.TCAN-014 "
        )

        # cannot stake with rune in memo
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
            "STAKE:" + RUNE,
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
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "invalid stake memo:invalid pool asset")

        # cannot stake with > 2 coins
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [
                Coin("BNB.BNB", 150000000),
                Coin(RUNE, 50000000000),
                Coin("BNB-LOK-3C0", 30000000000),
            ],
            "STAKE:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

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
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "refund reason message")  # FIXME

        # can stake with only asset
        txn = Transaction(
            Binance.chain,
            "STAKER-2",
            "VAULT",
            [Coin("BNB.BNB", 30000000)],
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
        self.assertEqual(event.event.pool, pool.asset)
        self.assertEqual(event.event.stake_units, 2090833333)

        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin(RUNE, 10000000000)],
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
        self.assertEqual(event.event.pool, pool.asset)
        self.assertEqual(event.event.stake_units, 2507500000)

        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin(RUNE, 30000000000), Coin("BNB.BNB", 90000000)],
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
        self.assertEqual(event.event.pool, pool.asset)
        self.assertEqual(event.event.stake_units, 15045000000)

    def test_unstake(self):
        thorchain = ThorchainState()
        # stake some funds into a pool
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
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
            Binance.chain, "STAKER-1", "VAULT", [Coin(RUNE, 1)], "WITHDRAW:BNB.BNB:100",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)
        self.assertEqual(outbound[0].coins[0].asset, RUNE)
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
        self.assertEqual(event.event.pool, "BNB.BNB")
        self.assertEqual(event.event.stake_units, 250750000)
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
        self.assertEqual(event.event.code, 105)
        self.assertEqual(event.event.reason, "Invalid symbol")

        # check successful withdraw everything
        txn = Transaction(
            Binance.chain, "STAKER-1", "VAULT", [Coin(RUNE, 1)], "WITHDRAW:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)
        self.assertEqual(outbound[0].coins[0].asset, RUNE)
        self.assertEqual(outbound[0].coins[0].amount, 49500000000)
        self.assertEqual(outbound[1].coins[0].asset, "BNB.BNB")
        self.assertEqual(outbound[1].coins[0].amount, 148425000)

        pool = thorchain.get_pool("BNB.BNB")
        self.assertEqual(pool.rune_balance, 0)
        self.assertEqual(pool.asset_balance, 75000)
        self.assertEqual(pool.get_staker("STAKER-1").units, 0)
        self.assertEqual(pool.total_units, 0)

        # check event generated for successful unstake
        events = thorchain.get_events()
        self.assertEqual(len(events), 7)
        # we get 2 new events

        # first new event = pool event bootstrap
        event = events[5]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "pool")
        self.assertEqual(event.in_tx.to_json(), Transaction.empty_txn().to_json())
        self.assertEqual(event.out_txs, [])
        self.assertEqual(event.event.pool, "BNB.BNB")
        self.assertEqual(event.event.status, "Bootstrap")

        # second new event = unstake event
        event = events[6]
        self.assertEqual(event.status, "Success")
        self.assertEqual(event.type, "unstake")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
        self.assertEqual(event.out_txs[1].to_json(), outbound[1].to_json())
        self.assertEqual(event.event.pool, "BNB.BNB")
        self.assertEqual(event.event.stake_units, 24824250000)
        self.assertEqual(event.event.basis_points, 10000)
        self.assertEqual(event.event.asymmetry, 0)

        # check withdraw staker has 0 units
        txn = Transaction(
            Binance.chain, "STAKER-1", "VAULT", [Coin(RUNE, 1)], "WITHDRAW:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].coins[0].asset, RUNE)
        self.assertEqual(outbound[0].coins[0].amount, 1)

        pool = thorchain.get_pool("BNB.BNB")
        self.assertEqual(pool.rune_balance, 0)
        self.assertEqual(pool.asset_balance, 75000)
        self.assertEqual(pool.get_staker("STAKER-1").units, 0)
        self.assertEqual(pool.total_units, 0)

        # check refund event generated for unstake with 0 units left
        events = thorchain.get_events()
        self.assertEqual(len(events), 8)
        event = events[7]
        self.assertEqual(event.status, "Refund")
        self.assertEqual(event.type, "refund")
        self.assertEqual(event.in_tx.to_json(), txn.to_json())
        self.assertEqual(len(event.out_txs), len(outbound))
        self.assertEqual(event.out_txs[0].to_json(), outbound[0].to_json())
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
        slip = thorchain._calc_trade_slip(94405967833, 10000000000)
        self.assertEqual(slip, 2231)

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
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
            "STAKE:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 0)

        # stake some funds into a pool
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.LOK-3C0", 150000000), Coin(RUNE, 50000000000)],
            "STAKE:BNB.LOK-3C0",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 0)

        # unstake
        txn = Transaction(
            Binance.chain, "STAKER-1", "VAULT", [Coin(RUNE, 1)], "WITHDRAW:BNB.BNB:100",
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
    def test_get(self):
        swap = Event(
            "swap",
            [
                {"in_tx_id": "FAAFF"},
                {"id": "TODO"},
                {"chain": "BNB"},
                {"from": "tbnb1zge452mgjg9508edxqfpzfl3sfc7vakf2mprqj"},
                {"to": "tbnb189az9plcke2c00vns0zfmllfpfdw67dtv25kgx"},
                {"coin": "149700000 BNB.BNB"},
                {"memo": "REFUND:FAAFF"},
            ],
        )
        txid = swap.get("id")
        self.assertEqual(txid, "TODO")
        memo = swap.get("memo")
        self.assertEqual(memo, "REFUND:FAAFF")
        random = swap.get("random")
        self.assertEqual(random, None)

    def test_eq(self):
        outbound_sim = Event(
            "outbound",
            [
                {"in_tx_id": "FAAFF"},
                {"id": "TODO"},
                {"chain": "BNB"},
                {"from": "tbnb1zge452mgjg9508edxqfpzfl3sfc7vakf2mprqj"},
                {"to": "tbnb189az9plcke2c00vns0zfmllfpfdw67dtv25kgx"},
                {"coin": "149700000 BNB.BNB"},
                {"memo": "REFUND:FAAFF"},
            ],
        )
        outbound = Event(
            "outbound",
            [
                {"in_tx_id": "FAAFF"},
                {"id": "67672"},
                {"chain": "BNB"},
                {"from": "tbnb1zge452mgjg9508edxqfpzfl3sfc7vakf2mprqj"},
                {"to": "tbnb189az9plcke2c00vns0zfmllfpfdw67dtv25kgx"},
                {"coin": "149700000 BNB.BNB"},
                {"memo": "REFUND:FAAFF"},
            ],
        )
        self.assertEqual(outbound_sim, outbound)
        swap_sim = Event(
            "swap",
            [
                {"in_tx_id": "FAAFF"},
                {"id": "TODO"},
                {"chain": "BNB"},
                {"from": "tbnb1zge452mgjg9508edxqfpzfl3sfc7vakf2mprqj"},
                {"to": "tbnb189az9plcke2c00vns0zfmllfpfdw67dtv25kgx"},
                {"coin": "149700000 BNB.BNB"},
                {"memo": "REFUND:FAAFF"},
            ],
        )
        swap = Event(
            "swap",
            [
                {"in_tx_id": "FAAFF"},
                {"id": "67672"},
                {"chain": "BNB"},
                {"from": "tbnb1zge452mgjg9508edxqfpzfl3sfc7vakf2mprqj"},
                {"to": "tbnb189az9plcke2c00vns0zfmllfpfdw67dtv25kgx"},
                {"coin": "149700000 BNB.BNB"},
                {"memo": "REFUND:FAAFF"},
            ],
        )
        self.assertNotEqual(swap_sim, swap)

    def test_sort_events(self):
        evt1 = Event("test", ["id": 1], 1, "block")
        evt2 = Event("test", ["id": 2], 1, "tx")
        evt3 = Event("test", ["id": 3], 6, "block")
        evt4 = Event("test", ["id": 4], 3, "tx")
        evt5 = Event("test", ["id": 5], 3, "block")
        evt6 = Event("test", ["id": 6], 2, "block")
        events = [evt1, evt2, evt3, evt4, evt5, evt6]
        expected_events = [evt2, evt1, evt6, evt4, evt5, evt3]
        ThorchainClient.sort_events(events)
        self.assertEqual(events, expected_events)

    def test_sorted(self):
        outbound_sim_1 = Event(
            "outbound",
            [
                {"in_tx_id": "FAAFF"},
                {"id": "TODO"},
                {"chain": "BNB"},
                {"from": "tbnb1zge452mgjg9508edxqfpzfl3sfc7vakf2mprqj"},
                {"to": "tbnb189az9plcke2c00vns0zfmllfpfdw67dtv25kgx"},
                {"coin": "149700000 BNB.BNB"},
                {"memo": "REFUND:FAAFF"},
            ],
        )
        outbound_sim_2 = Event(
            "outbound",
            [
                {"in_tx_id": "FAAFF"},
                {"id": "TODO"},
                {"chain": "BNB"},
                {"from": "tbnb1zge452mgjg9508edxqfpzfl3sfc7vakf2mprqj"},
                {"to": "tbnb189az9plcke2c00vns0zfmllfpfdw67dtv25kgx"},
                {"coin": "500000000 BNB.RUNE-A1F"},
                {"memo": "REFUND:FAAFF"},
            ],
        )
        sim_events = [outbound_sim_1, outbound_sim_2]
        outbound_1 = Event(
            "outbound",
            [
                {"in_tx_id": "FAAFF"},
                {"id": "47AC6"},
                {"chain": "BNB"},
                {"from": "tbnb1zge452mgjg9508edxqfpzfl3sfc7vakf2mprqj"},
                {"to": "tbnb189az9plcke2c00vns0zfmllfpfdw67dtv25kgx"},
                {"coin": "149700000 BNB.BNB"},
                {"memo": "REFUND:FAAFF"},
            ],
        )
        outbound_2 = Event(
            "outbound",
            [
                {"in_tx_id": "FAAFF"},
                {"id": "E415A"},
                {"chain": "BNB"},
                {"from": "tbnb1zge452mgjg9508edxqfpzfl3sfc7vakf2mprqj"},
                {"to": "tbnb189az9plcke2c00vns0zfmllfpfdw67dtv25kgx"},
                {"coin": "500000000 BNB.RUNE-A1F"},
                {"memo": "REFUND:FAAFF"},
            ],
        )
        sim_events = [outbound_sim_1, outbound_sim_2]
        events = [outbound_1, outbound_2]
        self.assertEqual(sim_events, events)
        events = [outbound_2, outbound_1]
        self.assertNotEqual(sim_events, events)
        self.assertEqual(sorted(sim_events), sorted(events))


if __name__ == "__main__":
    unittest.main()
