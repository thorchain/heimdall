import unittest
import json

from copy import deepcopy
from utils.common import Asset, Transaction, Coin, get_share, get_rune_asset
from chains.binance import Binance

RUNE=get_rune_asset()

class TestAsset(unittest.TestCase):
    def test_constructor(self):
        asset = Asset("BNB.BNB")
        self.assertEqual(asset, "BNB.BNB")
        asset = Asset("BNB")
        self.assertEqual(asset, "THOR.BNB")
        asset = Asset(RUNE)
        self.assertEqual(asset, RUNE)
        asset = Asset(RUNE)
        self.assertEqual(asset, RUNE)
        asset = Asset("BNB.LOK-3C0")
        self.assertEqual(asset, "BNB.LOK-3C0")

    def test_get_share(self):
        alloc = 50000000
        part = 149506590
        total = 50165561086
        share = get_share(part, total, alloc)
        self.assertEqual(share, 149013)

    def test_get_symbol(self):
        asset = Asset("BNB.BNB")
        self.assertEqual(asset.get_symbol(), "BNB")
        asset = Asset(RUNE)
        self.assertEqual(asset.get_symbol(), RUNE.split('.')[-1])
        asset = Asset("LOK-3C0")
        self.assertEqual(asset.get_symbol(), "LOK-3C0")

    def test_get_chain(self):
        asset = Asset("BNB.BNB")
        self.assertEqual(asset.get_chain(), "BNB")
        asset = Asset(RUNE)
        self.assertEqual(asset.get_chain(), RUNE.split('.')[0])
        asset = Asset("LOK-3C0")
        self.assertEqual(asset.get_chain(), "THOR")

    def test_is_rune(self):
        asset = Asset("BNB.BNB")
        self.assertEqual(asset.is_rune(), False)
        asset = Asset(RUNE)
        self.assertEqual(asset.is_rune(), True)
        asset = Asset("LOK-3C0")
        self.assertEqual(asset.is_rune(), False)
        asset = Asset("RUNE")
        self.assertEqual(asset.is_rune(), True)

    def test_to_json(self):
        asset = Asset("BNB.BNB")
        self.assertEqual(asset.to_json(), json.dumps("BNB.BNB"))
        asset = Asset("BNB.LOK-3C0")
        self.assertEqual(asset.to_json(), json.dumps("BNB.LOK-3C0"))
        asset = Asset(RUNE)
        self.assertEqual(asset.to_json(), json.dumps(RUNE))


class TestCoin(unittest.TestCase):
    def test_constructor(self):
        coin = Coin("BNB.BNB", 100)
        self.assertEqual(coin.asset, "BNB.BNB")
        self.assertEqual(coin.amount, 100)
        coin = Coin("BNB.BNB")
        self.assertEqual(coin.asset, "BNB.BNB")
        self.assertEqual(coin.amount, 0)
        coin = Coin(RUNE, 1000000)
        self.assertEqual(coin.amount, 1000000)
        self.assertEqual(coin.asset, RUNE)

        coin = Coin(RUNE, 400_000 * 100000000)
        c = coin.__dict__
        self.assertEqual(c["amount"], 400_000 * 100000000)
        self.assertEqual(c["asset"], RUNE)

    def test_is_zero(self):
        coin = Coin("BNB.BNB", 100)
        self.assertEqual(coin.is_zero(), False)
        coin = Coin("BNB.BNB")
        self.assertEqual(coin.is_zero(), True)
        coin = Coin(RUNE, 0)
        self.assertEqual(coin.is_zero(), True)

    def test_eq(self):
        coin1 = Coin("BNB.BNB", 100)
        coin2 = Coin("BNB.BNB")
        self.assertNotEqual(coin1, coin2)
        coin1 = Coin("BNB.BNB", 100)
        coin2 = Coin("BNB.BNB", 100)
        self.assertEqual(coin1, coin2)
        coin1 = Coin("BNB.LOK-3C0", 100)
        coin2 = Coin(RUNE, 100)
        self.assertNotEqual(coin1, coin2)
        coin1 = Coin("BNB.LOK-3C0", 100)
        coin2 = Coin("BNB.LOK-3C0", 100)
        self.assertEqual(coin1, coin2)
        coin1 = Coin("LOK-3C0", 200)
        coin2 = Coin("LOK-3C0", 200)
        self.assertEqual(coin1, coin2)
        coin1 = Coin("RUNE")
        coin2 = Coin("RUNE")
        self.assertEqual(coin1, coin2)
        # check list equality
        list1 = [Coin("RUNE", 100), Coin("RUNE", 100)]
        list2 = [Coin("RUNE", 100), Coin("RUNE", 100)]
        self.assertEqual(list1, list2)
        list1 = [Coin("RUNE", 100), Coin("RUNE", 100)]
        list2 = [Coin("RUNE", 10), Coin("RUNE", 100)]
        self.assertNotEqual(list1, list2)
        # list not sorted are NOT equal
        list1 = [Coin("RUNE", 100), Coin("BNB.BNB", 200)]
        list2 = [Coin("BNB.BNB", 200), Coin("RUNE", 100)]
        self.assertNotEqual(list1, list2)
        self.assertEqual(sorted(list1), sorted(list2))
        # check sets
        list1 = [Coin("RUNE", 100), Coin("RUNE", 100)]
        self.assertEqual(len(set(list1)), 1)
        list1 = [Coin("RUNE", 100), Coin("RUNE", 10)]
        self.assertEqual(len(set(list1)), 2)

    def test_is_rune(self):
        coin = Coin("BNB.BNB")
        self.assertEqual(coin.is_rune(), False)
        coin = Coin(RUNE)
        self.assertEqual(coin.is_rune(), True)
        coin = Coin("LOK-3C0")
        self.assertEqual(coin.is_rune(), False)
        coin = Coin("RUNE")
        self.assertEqual(coin.is_rune(), True)

    def test_to_binance_fmt(self):
        coin = Coin("BNB.BNB")
        self.assertEqual(coin.to_binance_fmt(), {"denom": "BNB", "amount": 0})
        coin = Coin("RUNE", 1000000)
        self.assertEqual(coin.to_binance_fmt(), {"denom": "RUNE", "amount": 1000000})
        coin = Coin("LOK-3C0", 1000000)
        self.assertEqual(coin.to_binance_fmt(), {"denom": "LOK-3C0", "amount": 1000000})

    def test_str(self):
        coin = Coin("BNB.BNB")
        self.assertEqual(str(coin), "0_BNB.BNB")
        coin = Coin(RUNE, 1000000)
        self.assertEqual(str(coin), "1,000,000_" + RUNE)
        coin = Coin("BNB.LOK-3C0", 1000000)
        self.assertEqual(str(coin), "1,000,000_BNB.LOK-3C0")

    def test_repr(self):
        coin = Coin("BNB.BNB")
        self.assertEqual(repr(coin), "<Coin 0_BNB.BNB>")
        coin = Coin(RUNE, 1000000)
        self.assertEqual(repr(coin), f"<Coin 1,000,000_{RUNE}>")
        coin = Coin("BNB.LOK-3C0", 1000000)
        self.assertEqual(repr(coin), "<Coin 1,000,000_BNB.LOK-3C0>")

    def test_to_json(self):
        coin = Coin("BNB.BNB")
        self.assertEqual(coin.to_json(), '{"asset": "BNB.BNB", "amount": 0}')
        coin = Coin(RUNE, 1000000)
        self.assertEqual(coin.to_json(), '{"asset": "'+RUNE+'", "amount": 1000000}')
        coin = Coin("BNB.LOK-3C0", 1000000)
        self.assertEqual(coin.to_json(), '{"asset": "BNB.LOK-3C0", "amount": 1000000}')

    def test_from_dict(self):
        value = {
            "asset": "BNB.BNB",
            "amount": 1000,
        }
        coin = Coin.from_dict(value)
        self.assertEqual(coin.asset, "BNB.BNB")
        self.assertEqual(coin.amount, 1000)
        value = {
            "asset": RUNE,
            "amount": "1000",
        }
        coin = Coin.from_dict(value)
        self.assertEqual(coin.asset, RUNE)
        self.assertEqual(coin.amount, 1000)


class TestTransaction(unittest.TestCase):
    def test_constructor(self):
        txn = Transaction(Binance.chain, "USER", "VAULT", Coin("BNB.BNB", 100), "MEMO",)
        self.assertEqual(txn.chain, "BNB")
        self.assertEqual(txn.from_address, "USER")
        self.assertEqual(txn.to_address, "VAULT")
        self.assertEqual(txn.coins[0].asset, "BNB.BNB")
        self.assertEqual(txn.coins[0].amount, 100)
        self.assertEqual(txn.memo, "MEMO")
        txn.coins = [Coin("BNB.BNB", 1000000000), Coin(RUNE, 1000000000)]
        self.assertEqual(txn.coins[0].asset, "BNB.BNB")
        self.assertEqual(txn.coins[0].amount, 1000000000)
        self.assertEqual(txn.coins[1].asset, RUNE)
        self.assertEqual(txn.coins[1].amount, 1000000000)

    def test_str(self):
        txn = Transaction(Binance.chain, "USER", "VAULT", Coin("BNB.BNB", 100), "MEMO",)
        self.assertEqual(str(txn), "Tx     USER ==> VAULT    | MEMO | 100_BNB.BNB")
        txn.coins = [Coin("BNB.BNB", 1000000000), Coin(RUNE, 1000000000)]
        self.assertEqual(
            str(txn),
            "Tx     USER ==> VAULT    | MEMO | 1,000,000,000_BNB.BNB"
            f", 1,000,000,000_{RUNE}",
        )
        txn.coins = None
        self.assertEqual(
            str(txn), "Tx     USER ==> VAULT    | MEMO | No Coins",
        )
        txn.gas = [Coin("BNB.BNB", 37500)]
        self.assertEqual(
            str(txn), "Tx     USER ==> VAULT    | MEMO | No Coins | Gas 37,500_BNB.BNB",
        )

    def test_repr(self):
        txn = Transaction(Binance.chain, "USER", "VAULT", Coin("BNB.BNB", 100), "MEMO",)
        self.assertEqual(
            repr(txn), "<Tx     USER ==> VAULT    | MEMO | [<Coin 100_BNB.BNB>]>"
        )
        txn.coins = [Coin("BNB.BNB", 1000000000), Coin(RUNE, 1000000000)]
        self.assertEqual(
            repr(txn),
            "<Tx     USER ==> VAULT    | MEMO | [<Coin 1,000,000,000_BNB.BNB>,"
            f" <Coin 1,000,000,000_{RUNE}>]>",
        )
        txn.coins = None
        self.assertEqual(
            repr(txn), "<Tx     USER ==> VAULT    | MEMO | No Coins>",
        )
        txn.gas = [Coin("BNB.BNB", 37500)]
        self.assertEqual(
            repr(txn),
            "<Tx     USER ==> VAULT    | MEMO | No Coins |"
            " Gas [<Coin 37,500_BNB.BNB>]>",
        )

    def test_eq(self):
        tx1 = Transaction(
            Binance.chain, "USER", "VAULT", Coin("BNB.BNB", 100), "STAKE:BNB",
        )
        tx2 = Transaction(
            Binance.chain, "USER", "VAULT", Coin("BNB.BNB", 100), "STAKE:BNB",
        )
        self.assertEqual(tx1, tx2)
        tx2.chain = "BTC"
        self.assertNotEqual(tx1, tx2)
        tx1 = Transaction(
            Binance.chain, "USER", "VAULT", [Coin("BNB.BNB", 100)], "STAKE:BNB",
        )
        tx2 = Transaction(
            Binance.chain, "USER", "VAULT", [Coin("BNB.BNB", 100)], "STAKE:BNB",
        )
        self.assertEqual(tx1, tx2)
        tx1.memo = "STAKE:BNB"
        tx2.memo = "ADD:BNB"
        self.assertNotEqual(tx1, tx2)
        tx1.memo = "STAKE"
        tx2.memo = "ADD"
        self.assertNotEqual(tx1, tx2)
        tx1.memo = ""
        tx2.memo = ""
        self.assertEqual(tx1, tx2)
        tx1.memo = "Hello"
        tx2.memo = ""
        self.assertNotEqual(tx1, tx2)
        # we ignore addresses in memo
        tx1.memo = "REFUND:ADDRESS"
        tx2.memo = "REFUND:TODO"
        self.assertNotEqual(tx1, tx2)
        # we dont ignore different assets though
        tx1.memo = "STAKE:BNB"
        tx2.memo = "STAKE:RUNE"
        self.assertNotEqual(tx1, tx2)
        tx2.memo = "STAKE:BNB"
        self.assertEqual(tx1, tx2)
        tx2.coins = [Coin("BNB.BNB", 100)]
        self.assertEqual(tx1, tx2)
        tx2.coins = [Coin("BNB.BNB", 100), Coin("RUNE", 100)]
        self.assertNotEqual(tx1, tx2)
        # different list of coins not equal
        tx1.coins = [Coin("RUNE", 200), Coin("RUNE", 100)]
        tx2.coins = [Coin("BNB.BNB", 100), Coin("RUNE", 200)]
        self.assertNotEqual(tx1, tx2)
        # coins different order tx are still equal
        tx1.coins = [Coin("RUNE", 200), Coin("BNB.BNB", 100)]
        tx2.coins = [Coin("BNB.BNB", 100), Coin("RUNE", 200)]
        self.assertEqual(tx1, tx2)
        # we ignore from / to address for equality
        tx1.to_address = "VAULT1"
        tx2.to_address = "VAULT2"
        tx1.from_address = "USER1"
        tx2.from_address = "USER2"
        self.assertNotEqual(tx1, tx2)
        # check list of transactions equality
        tx1 = Transaction(
            Binance.chain, "USER", "VAULT", [Coin("BNB.BNB", 100)], "STAKE:BNB",
        )
        tx2 = deepcopy(tx1)
        tx3 = deepcopy(tx1)
        tx4 = deepcopy(tx1)
        list1 = [tx1, tx2]
        list2 = [tx3, tx4]
        self.assertEqual(list1, list2)

        # check sort list of transactions get sorted by smallest coin
        # check list of 1 coin
        # descending order in list1
        tx1.coins = [Coin("RUNE", 200)]
        tx2.coins = [Coin("BNB.BNB", 100)]
        # ascrending order in list2
        tx3.coins = [Coin("BNB.BNB", 100)]
        tx4.coins = [Coin("RUNE", 200)]
        self.assertNotEqual(list1, list2)
        self.assertEqual(sorted(list1), list2)
        self.assertEqual(sorted(list1), sorted(list2))

        # check list of > 1 coin
        # descending order in list1
        tx1.coins = [Coin("RUNE", 200), Coin("BNB.BNB", 300)]
        tx2.coins = [Coin("BNB.BNB", 100), Coin("LOK-3C0", 500)]
        # ascrending order in list2
        tx3.coins = [Coin("BNB.BNB", 100), Coin("LOK-3C0", 500)]
        tx4.coins = [Coin("RUNE", 200), Coin("BNB.BNB", 300)]
        self.assertNotEqual(list1, list2)
        self.assertEqual(sorted(list1), list2)
        self.assertEqual(sorted(list1), sorted(list2))

        # check 1 tx with no coins
        list1 = sorted(list1)
        self.assertEqual(list1, list2)
        list1[0].coins = None
        self.assertNotEqual(list1, list2)
        list2[0].coins = None
        self.assertEqual(list1, list2)

    def test_custom_hash(self):
        txn = Transaction(
            Binance.chain,
            "USER",
            "tbnb1yxfyeda8pnlxlmx0z3cwx74w9xevspwdpzdxpj",
            Coin("BNB.BNB", 194765912),
            "REFUND:TODO",
            id="9999A5A08D8FCF942E1AAAA01AB1E521B699BA3A009FA0591C011DC1FFDC5E68",
        )
        self.assertEqual(
            txn.custom_hash(""),
            "FE64709713A9F9D691CF2C5B144CA6DAA53E902800C1367C692FE7935BD029CE",
        )
        txn.coins = None
        self.assertEqual(
            txn.custom_hash(""),
            "229BD31DB372A43FB71896BDE7512BFCA06731A4D825B4721A1D8DD800159DCD",
        )
        txn.to_address = "tbnb189az9plcke2c00vns0zfmllfpfdw67dtv25kgx"
        txn.coins = [Coin(RUNE, 49900000000)]
        txn.memo = (
            "REFUND:CA3A36052DC2FC30B91AD3996012E9EF2E69EEA70D5FBBBD9364F6F97A056D7C"
        )
        pubkey = (
            "thorpub1addwnpepqv7kdf473gc4jyls7hlx4rg"
            "t2lqxm9qkfh5m3ua7wnzzzfhlpz49u4slu4g"
        )
        self.assertEqual(
            txn.custom_hash(pubkey),
            "2CA3A2B2A758ABD7F464C51071C0E0DAC39D7583F418D98FF9D30894CDB7FF49",
        )

    def test_to_json(self):
        txn = Transaction(
            Binance.chain, "USER", "VAULT", Coin("BNB.BNB", 100), "STAKE:BNB",
        )
        self.assertEqual(
            txn.to_json(),
            '{"id": "TODO", "chain": "BNB", "from_address": "USER", '
            '"to_address": "VAULT", "memo": "STAKE:BNB", "coins": '
            '[{"asset": "BNB.BNB", "amount": 100}], "gas": null}',
        )
        txn.coins = [Coin("BNB.BNB", 1000000000), Coin(RUNE, 1000000000)]
        self.assertEqual(
            txn.to_json(),
            '{"id": "TODO", "chain": "BNB", "from_address": "USER", '
            '"to_address": "VAULT", "memo": "STAKE:BNB", "coins": ['
            '{"asset": "BNB.BNB", "amount": 1000000000}, '
            '{"asset": "' + RUNE + '", "amount": 1000000000}], "gas": null}',
        )
        txn.coins = None
        self.assertEqual(
            txn.to_json(),
            '{"id": "TODO", "chain": "BNB", "from_address": "USER", '
            '"to_address": "VAULT", "memo": "STAKE:BNB", "coins": null, "gas": null}',
        )
        txn.gas = [Coin("BNB.BNB", 37500)]
        self.assertEqual(
            txn.to_json(),
            '{"id": "TODO", "chain": "BNB", "from_address": "USER", '
            '"to_address": "VAULT", "memo": "STAKE:BNB", "coins": null,'
            ' "gas": [{"asset": "BNB.BNB", "amount": 37500}]}',
        )

    def test_from_dict(self):
        value = {
            "chain": "BNB",
            "from_address": "USER",
            "to_address": "VAULT",
            "coins": [
                {"asset": "BNB.BNB", "amount": 1000},
                {"asset": RUNE, "amount": "1000"},
            ],
            "memo": "STAKE:BNB.BNB",
        }
        txn = Transaction.from_dict(value)
        self.assertEqual(txn.chain, "BNB")
        self.assertEqual(txn.from_address, "USER")
        self.assertEqual(txn.to_address, "VAULT")
        self.assertEqual(txn.memo, "STAKE:BNB.BNB")
        self.assertEqual(txn.coins[0].asset, "BNB.BNB")
        self.assertEqual(txn.coins[0].amount, 1000)
        self.assertEqual(txn.coins[1].asset, RUNE)
        self.assertEqual(txn.coins[1].amount, 1000)
        self.assertEqual(txn.gas, None)
        value["coins"] = None
        value["gas"] = [{"asset": "BNB.BNB", "amount": "37500"}]
        txn = Transaction.from_dict(value)
        self.assertEqual(txn.chain, "BNB")
        self.assertEqual(txn.from_address, "USER")
        self.assertEqual(txn.to_address, "VAULT")
        self.assertEqual(txn.memo, "STAKE:BNB.BNB")
        self.assertEqual(txn.coins, None)
        self.assertEqual(txn.gas[0].asset, "BNB.BNB")
        self.assertEqual(txn.gas[0].amount, 37500)


if __name__ == "__main__":
    unittest.main()
