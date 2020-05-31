import unittest

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
        expected_events = [
            Event(
                "refund",
                [
                    {"code": "105"},
                    {"reason": "refund reason message: pool is zero"},
                    *txn.get_attributes(),
                ],
            ),
            Event(
                "fee",
                [
                    {"tx_id": "TODO"},
                    {"coins": f"100000000 {RUNE}"},
                    {"pool_deduct": "0"},
                ],
            ),
        ]
        self.assertEqual(events, expected_events)

        # do a regular swap
        thorchain.pools = [Pool("BNB.BNB", 50 * 100000000, 50 * 100000000)]
        outbound = thorchain.handle(txn)
        outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "OUTBOUND:TODO")
        self.assertEqual(outbound[0].coins[0].asset, "BNB.BNB")
        self.assertEqual(outbound[0].coins[0].amount, 622685185)

        # check swap event generated for successful swap
        expected_events += [
            Event(
                "swap",
                [
                    {"pool": "BNB.BNB"},
                    {"price_target": "0"},
                    {"trade_slip": "4400"},
                    {"liquidity_fee": "138888888"},
                    {"liquidity_fee_in_rune": "138888888"},
                    *txn.get_attributes(),
                ],
            ),
            Event(
                "fee",
                [
                    {"tx_id": "TODO"},
                    {"coins": "71759259 BNB.BNB"},
                    {"pool_deduct": "100000000"},
                ],
            ),
        ]
        self.assertEqual(events, expected_events)

        # swap with two coins on the inbound tx
        txn.coins = [Coin("BNB.BNB", 1000000000), Coin(RUNE, 1000000000)]
        outbound = thorchain.handle(txn)
        outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 2)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")

        # check refund event generated for swap with two coins
        reason = "invalid swap memo:not expecting multiple coins in a swap"
        expected_events += [
            Event(
                "refund", [{"code": "105"}, {"reason": reason}, *txn.get_attributes()],
            ),
            Event(
                "fee",
                [
                    {"tx_id": "TODO"},
                    {"coins": "74191777 BNB.BNB"},
                    {"pool_deduct": "100000000"},
                ],
            ),
            Event(
                "fee",
                [
                    {"tx_id": "TODO"},
                    {"coins": f"100000000 {RUNE}"},
                    {"pool_deduct": "0"},
                ],
            ),
        ]
        self.assertEqual(events, expected_events)

        # swap with zero return, refunds and doesn't change pools
        txn.coins = [Coin(RUNE, 1)]
        outbound = thorchain.handle(txn)
        # outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")
        self.assertEqual(thorchain.pools[0].rune_balance, 58 * 100000000)

        # check refund event generated for swap with zero return
        # check refund event generated for swap with two coins
        expected_events += [
            Event(
                "refund",
                [
                    {"code": "108"},
                    {"reason": "emit asset 0 less than price limit 0"},
                    *txn.get_attributes(),
                ],
            ),
        ]
        self.assertEqual(events, expected_events)

        # swap with zero return, not enough coin to pay fee so no refund
        txn.coins = [Coin(RUNE, 1)]
        outbound = thorchain.handle(txn)
        outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 0)
        self.assertEqual(thorchain.pools[0].rune_balance, 58 * 100000000)

        # check refund event generated for swap with zero return
        expected_events += [
            Event(
                "refund",
                [
                    {"code": "108"},
                    {"reason": "emit asset 0 less than price limit 0"},
                    *txn.get_attributes(),
                ],
            ),
            Event(
                "fee",
                [
                    {"tx_id": "TODO"},
                    {"coins": f"100000000 {RUNE}"},
                    {"pool_deduct": "0"},
                ],
            ),
        ]
        self.assertEqual(events, expected_events)

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
        reason = "emit asset 325254953 less than price limit 999999999999999999999"
        expected_events += [
            Event(
                "refund", [{"code": "108"}, {"reason": reason}, *txn.get_attributes()],
            ),
            Event(
                "fee",
                [
                    {"tx_id": "TODO"},
                    {"coins": f"100000000 {RUNE}"},
                    {"pool_deduct": "0"},
                ],
            ),
        ]
        self.assertEqual(events, expected_events)

        # swap with custom address
        txn.coins = [Coin(RUNE, 500000000)]
        txn.memo = "SWAP:BNB.BNB:NOMNOM:"
        outbound = thorchain.handle(txn)
        outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "OUTBOUND:TODO")
        self.assertEqual(outbound[0].to_address, "NOMNOM")

        # check swap event generated for successful swap
        expected_events += [
            Event(
                "swap",
                [
                    {"pool": "BNB.BNB"},
                    {"price_target": "0"},
                    {"trade_slip": "1798"},
                    {"liquidity_fee": "28039220"},
                    {"liquidity_fee_in_rune": "36533132"},
                    *txn.get_attributes(),
                ],
            ),
            Event(
                "fee",
                [
                    {"tx_id": "TODO"},
                    {"coins": "65496058 BNB.BNB"},
                    {"pool_deduct": "100000000"},
                ],
            ),
        ]
        self.assertEqual(events, expected_events)

        # refund swap when address is a different network
        txn.coins = [Coin(RUNE, 500000000)]
        txn.memo = "SWAP:BNB.BNB:BNBNOMNOM"
        outbound = thorchain.handle(txn)
        outbound = thorchain.handle_fee(txn, outbound)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")

        # check refund event generated for swap with different network
        expected_events += [
            Event(
                "refund",
                [
                    {"code": "105"},
                    {"reason": "address format not supported: BNBNOMNOM"},
                    *txn.get_attributes(),
                ],
            ),
            Event(
                "fee",
                [
                    {"tx_id": "TODO"},
                    {"coins": f"100000000 {RUNE}"},
                    {"pool_deduct": "0"},
                ],
            ),
        ]
        self.assertEqual(events, expected_events)

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
        expected_events += [
            Event(
                "outbound",
                [
                    {"in_tx_id": txn.id},
                    {"id": Transaction.empty_id},
                    {"chain": RUNE.get_chain()},
                    {"from": "STAKER-1"},
                    {"to": "VAULT"},
                    {"coin": f"964183435 {RUNE}"},
                    {"memo": "SWAP:BNB.LOK-3C0"},
                ],
            ),
            Event(
                "swap",
                [
                    {"pool": "BNB.BNB"},
                    {"price_target": "0"},
                    {"trade_slip": "5340"},
                    {"liquidity_fee": "230019434"},
                    {"liquidity_fee_in_rune": "230019434"},
                    *txn.get_attributes(),
                ],
            ),
            Event(
                "swap",
                [
                    {"pool": "BNB.LOK-3C0"},
                    {"price_target": "0"},
                    {"trade_slip": "7461"},
                    {"liquidity_fee": "177473331"},
                    {"liquidity_fee_in_rune": "177473331"},
                    {"id": "TODO"},
                    {"chain": "BNB"},
                    {"from": "STAKER-1"},
                    {"to": "VAULT"},
                    {"coin": f"964183435 {RUNE}"},
                    {"memo": "SWAP:BNB.LOK-3C0"},
                ],
            ),
            Event(
                "fee",
                [
                    {"tx_id": "TODO"},
                    {"coins": "61747954 BNB.LOK-3C0"},
                    {"pool_deduct": "100000000"},
                ],
            ),
        ]
        self.assertEqual(events, expected_events)

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
        expected_events = [
            Event("add", [{"pool": "BNB.BNB"}, *txn.get_attributes()]),
        ]
        self.assertEqual(thorchain.events, expected_events)

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
        expected_events += [
            Event(
                "refund",
                [{"code": "105"}, {"reason": "Invalid symbol"}, *txn.get_attributes()],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

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
        expected_events += [
            Event(
                "refund",
                [{"code": "105"}, {"reason": "Invalid symbol"}, *txn.get_attributes()],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

        # cannot add with rune in memo
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
            f"ADD:{RUNE}",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # check refund event generated for add with rune in memo
        expected_events += [
            Event(
                "refund",
                [{"code": "105"}, {"reason": "Invalid symbol"}, *txn.get_attributes()],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

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
        expected_events += [
            Event(
                "refund",
                [
                    {"code": "105"},
                    {"reason": "refund reason message"},
                    *txn.get_attributes(),
                ],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

    def test_reserve(self):
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain, "STAKER-1", "VAULT", [Coin(RUNE, 50000000000)], "RESERVE",
        )

        outbound = thorchain.handle(txn)
        self.assertEqual(outbound, [])

        self.assertEqual(thorchain.reserve, 50000000000)

        # check event generated for successful reserve
        expected_events = [
            Event(
                "reserve",
                [
                    {"contributor_address": txn.from_address},
                    {"amount": txn.coins[0].amount},
                    *txn.get_attributes(),
                ],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

    def test_gas(self):
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
            "STAKE:BNB.BNB:STAKER-1",
        )

        outbound = thorchain.handle(txn)
        self.assertEqual(outbound, [])

        pool = thorchain.get_pool("BNB.BNB")
        self.assertEqual(pool.rune_balance, 50000000000)
        self.assertEqual(pool.asset_balance, 150000000)
        self.assertEqual(pool.get_staker("STAKER-1").units, 25075000000)
        self.assertEqual(pool.total_units, 25075000000)

        # check event generated for successful stake
        expected_events = [
            Event(
                "stake",
                [
                    {"pool": pool.asset},
                    {"stake_units": pool.total_units},
                    {"rune_address": txn.from_address},
                    {"rune_amount": "50000000000"},
                    {"asset_amount": "150000000"},
                    {"BNB_txid": "TODO"},
                ],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

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
        expected_events += [
            Event(
                "refund",
                [
                    {"code": "105"},
                    {"reason": "memo can't be empty"},
                    *txn.get_attributes(),
                ],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

        # check gas event generated after we sent to chain
        outbound[0].gas = [Coin("BNB.BNB", 37500)]
        outbound[1].gas = [Coin("BNB.BNB", 37500)]
        thorchain.handle_gas(outbound)

        # first new gas event
        expected_events += [
            Event(
                "gas",
                [
                    {"asset": "BNB.BNB"},
                    {"asset_amt": "75000"},
                    {"rune_amt": "25000000"},
                    {"transaction_count": "2"},
                ],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

    def test_stake(self):
        thorchain = ThorchainState()
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
            "STAKE:BNB.BNB:STAKER-1",
        )

        outbound = thorchain.handle(txn)
        self.assertEqual(outbound, [])

        pool = thorchain.get_pool("BNB.BNB")
        self.assertEqual(pool.rune_balance, 50000000000)
        self.assertEqual(pool.asset_balance, 150000000)
        self.assertEqual(pool.get_staker("STAKER-1").units, 25075000000)
        self.assertEqual(pool.total_units, 25075000000)

        # check event generated for successful stake
        expected_events = [
            Event(
                "stake",
                [
                    {"pool": pool.asset},
                    {"stake_units": pool.total_units},
                    {"rune_address": txn.from_address},
                    {"rune_amount": "50000000000"},
                    {"asset_amount": "150000000"},
                    {"BNB_txid": "TODO"},
                ],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

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
        expected_events += [
            Event(
                "refund",
                [
                    {"code": "105"},
                    {"reason": "memo can't be empty"},
                    *txn.get_attributes(),
                ],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

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
        expected_events += [
            Event(
                "refund",
                [{"code": "105"}, {"reason": "Invalid symbol"}, *txn.get_attributes()],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

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
        expected_events += [
            Event(
                "refund",
                [
                    {"code": "105"},
                    {"reason": "invalid stake memo:did not find BNB.TCAN-014 "},
                    *txn.get_attributes(),
                ],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

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
        expected_events += [
            Event(
                "refund",
                [
                    {"code": "105"},
                    {"reason": "invalid stake memo:invalid pool asset"},
                    *txn.get_attributes(),
                ],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

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
            "STAKE:BNB.BNB:STAKER-1",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)

        # check refund event generated for stake with > 2 coins
        expected_events += [
            Event(
                "refund",
                [
                    {"code": "105"},
                    {"reason": "refund reason message"},
                    *txn.get_attributes(),
                ],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

        # can stake with only asset
        txn = Transaction(
            Binance.chain,
            "STAKER-2",
            "VAULT",
            [Coin("BNB.BNB", 30000000)],
            "STAKE:BNB.BNB:STAKER-2",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 0)
        self.assertEqual(pool.get_staker("STAKER-2").units, 2090833333)
        self.assertEqual(pool.total_units, 27165833333)

        # check event generated for successful stake
        expected_events += [
            Event(
                "stake",
                [
                    {"pool": pool.asset},
                    {"stake_units": "2090833333"},
                    {"rune_address": "STAKER-2"},
                    {"rune_amount": "0"},
                    {"asset_amount": "30000000"},
                    {"BNB_txid": "TODO"},
                ],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin(RUNE, 10000000000)],
            "STAKE:BNB.BNB:STAKER-1",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 0)

        # check event generated for successful stake
        # only if BNB.RUNE-A1F as with native RUNE it would
        # be a cross chain stake and no event on first stake
        if RUNE.get_chain() == "BNB":
            expected_events += [
                Event(
                    "stake",
                    [
                        {"pool": pool.asset},
                        {"stake_units": "2507500000"},
                        {"rune_address": "STAKER-1"},
                        {"rune_amount": "10000000000"},
                        {"asset_amount": "0"},
                        {"BNB_txid": "TODO"},
                    ],
                ),
            ]
            self.assertEqual(thorchain.events, expected_events)

        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin(RUNE, 30000000000), Coin("BNB.BNB", 90000000)],
            "STAKE:BNB.BNB:STAKER-1",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 0)

        # check event generated for successful stake
        if RUNE.get_chain() == "BNB":
            expected_events += [
                Event(
                    "stake",
                    [
                        {"pool": pool.asset},
                        {"stake_units": "15045000000"},
                        {"rune_address": "STAKER-1"},
                        {"rune_amount": "30000000000"},
                        {"asset_amount": "90000000"},
                        {"BNB_txid": "TODO"},
                    ],
                ),
            ]
            self.assertEqual(thorchain.events, expected_events)

    def test_unstake(self):
        thorchain = ThorchainState()
        # stake some funds into a pool
        txn = Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB.BNB", 150000000), Coin(RUNE, 50000000000)],
            "STAKE:BNB.BNB:STAKER-1",
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
        expected_events = [
            Event(
                "stake",
                [
                    {"pool": pool.asset},
                    {"stake_units": "25075000000"},
                    {"rune_address": "STAKER-1"},
                    {"rune_amount": "50000000000"},
                    {"asset_amount": "150000000"},
                    {"BNB_txid": "TODO"},
                ],
            ),
            Event(
                "unstake",
                [
                    {"pool": "BNB.BNB"},
                    {"stake_units": "250750000"},
                    {"basis_points": "100"},
                    {"asymmetry": "0.000000000000000000"},
                    *txn.get_attributes(),
                ],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

        # should error without a pool referenced
        txn.memo = "WITHDRAW:"
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")

        # check refund event generated for unstake with bad memo
        expected_events += [
            Event(
                "refund",
                [{"code": "105"}, {"reason": "Invalid symbol"}, *txn.get_attributes()],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

        # should error without a bad withdraw basis points, should be between 0
        # and 10,000
        txn.memo = "WITHDRAW::-4"
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")

        # check refund event generated for unstake with bad withdraw basis points
        expected_events += [
            Event(
                "refund",
                [{"code": "105"}, {"reason": "Invalid symbol"}, *txn.get_attributes()],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

        txn.memo = "WITHDRAW::1000000000"
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0].memo, "REFUND:TODO")

        # check refund event generated for unstake with bad memo
        expected_events += [
            Event(
                "refund",
                [{"code": "105"}, {"reason": "Invalid symbol"}, *txn.get_attributes()],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

        # check successful withdraw everything
        txn = Transaction(
            Binance.chain, "STAKER-1", "VAULT", [Coin(RUNE, 1)], "WITHDRAW:BNB.BNB",
        )
        outbound = thorchain.handle(txn)
        self.assertEqual(len(outbound), 2)
        self.assertEqual(outbound[0].coins[0].asset, RUNE)
        self.assertEqual(outbound[0].coins[0].amount, 49500000000)
        self.assertEqual(outbound[1].coins[0].asset, "BNB.BNB")
        if RUNE.get_chain() == "BNB":
            self.assertEqual(outbound[1].coins[0].amount, 148425000)
        if RUNE.get_chain() == "THOR":
            self.assertEqual(outbound[1].coins[0].amount, 148462500)

        pool = thorchain.get_pool("BNB.BNB")
        self.assertEqual(pool.rune_balance, 0)
        self.assertEqual(pool.get_staker("STAKER-1").units, 0)
        self.assertEqual(pool.total_units, 0)
        if RUNE.get_chain() == "BNB":
            self.assertEqual(pool.asset_balance, 75000)
        if RUNE.get_chain() == "THOR":
            self.assertEqual(pool.asset_balance, 37500)

        # check event generated for successful unstake
        expected_events += [
            Event("pool", [{"pool": "BNB.BNB"}, {"pool_status": "Bootstrap"}]),
            Event(
                "unstake",
                [
                    {"pool": "BNB.BNB"},
                    {"stake_units": "24824250000"},
                    {"basis_points": "10000"},
                    {"asymmetry": "0.000000000000000000"},
                    *txn.get_attributes(),
                ],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

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
        self.assertEqual(pool.get_staker("STAKER-1").units, 0)
        self.assertEqual(pool.total_units, 0)
        if RUNE.get_chain() == "BNB":
            self.assertEqual(pool.asset_balance, 75000)
        if RUNE.get_chain() == "THOR":
            self.assertEqual(pool.asset_balance, 37500)

        # check refund event generated for unstake with 0 units left
        expected_events += [
            Event(
                "refund",
                [
                    {"code": "105"},
                    {"reason": "refund reason message"},
                    *txn.get_attributes(),
                ],
            ),
        ]
        self.assertEqual(thorchain.events, expected_events)

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
        swap_sim = Event(
            "swap",
            [
                {"pool": "ETH.ETH-0X0000000000000000000000000000000000000000"},
                {"stake_units": "27000000000"},
                {"rune_address": "tbnb1mkymsmnqenxthlmaa9f60kd6wgr9yjy9h5mz6q"},
                {"rune_amount": "50000000000"},
                {"asset_amount": "4000000000"},
                {"BNB_txid": "9573683032CBEE28E1A3C01648F"},
                {"ETH_txid": "FBBB33A59B9AA3F787743EC4176"},
            ],
        )
        swap = Event(
            "swap",
            [
                {"pool": "ETH.ETH-0x0000000000000000000000000000000000000000"},
                {"stake_units": "27000000000"},
                {"rune_address": "tbnb1mkymsmnqenxthlmaa9f60kd6wgr9yjy9h5mz6q"},
                {"rune_amount": "50000000000"},
                {"asset_amount": "4000000000"},
                {"ETH_txid": "FBBB33A59B9AA3F787743EC4176"},
                {"BNB_txid": "9573683032CBEE28E1A3C01648F"},
            ],
        )
        self.assertEqual(swap_sim, swap)

    def test_sort_events(self):
        evt1 = Event("test", [{"id": 1}], 1, "block")
        evt2 = Event("test", [{"id": 2}], 1, "tx")
        evt3 = Event("test", [{"id": 3}], 6, "block")
        evt4 = Event("test", [{"id": 4}], 3, "tx")
        evt5 = Event("test", [{"id": 5}], 3, "block")
        evt6 = Event("test", [{"id": 6}], 2, "block")
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
