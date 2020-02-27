import unittest
import json

from common import Asset, Transaction, Coin, delete_keys_from_dict
from chains import Binance


class TestUtils(unittest.TestCase):
    def test_delete_keys_from_dict(self):
        data = {
            "foo": {
                "bar": "bar",
                "list": [
                    "item", "item", "item",
                ],
            },
            "hello": "world",
            "data": "data",
        }
        delete_keys_from_dict(data, ["bar", "data"])
        expected = {
            "foo": {
                "list": [
                    "item", "item", "item",
                ],
            },
            "hello": "world",
        }
        self.assertEqual(data, expected)


class TestAsset(unittest.TestCase):
    def test_constructor(self):
        asset = Asset("BNB.BNB")
        self.assertEqual(asset, "BNB.BNB")
        asset = Asset("BNB")
        self.assertEqual(asset, "BNB.BNB")
        asset = Asset("RUNE-A1F")
        self.assertEqual(asset, "BNB.RUNE-A1F")
        asset = Asset("BNB.RUNE-A1F")
        self.assertEqual(asset, "BNB.RUNE-A1F")
        asset = Asset("BNB.LOK-3C0")
        self.assertEqual(asset, "BNB.LOK-3C0")

    def test_get_symbol(self):
        asset = Asset("BNB.BNB")
        self.assertEqual(asset.get_symbol(), "BNB")
        asset = Asset("BNB.RUNE-A1F")
        self.assertEqual(asset.get_symbol(), "RUNE-A1F")
        asset = Asset("LOK-3C0")
        self.assertEqual(asset.get_symbol(), "LOK-3C0")

    def test_get_chain(self):
        asset = Asset("BNB.BNB")
        self.assertEqual(asset.get_chain(), "BNB")
        asset = Asset("BNB.RUNE-A1F")
        self.assertEqual(asset.get_chain(), "BNB")
        asset = Asset("LOK-3C0")
        self.assertEqual(asset.get_chain(), "BNB")

    def test_is_rune(self):
        asset = Asset("BNB.BNB")
        self.assertEqual(asset.is_rune(), False)
        asset = Asset("BNB.RUNE-A1F")
        self.assertEqual(asset.is_rune(), True)
        asset = Asset("LOK-3C0")
        self.assertEqual(asset.is_rune(), False)
        asset = Asset("RUNE")
        self.assertEqual(asset.is_rune(), True)

    def test_to_json(self):
        asset = Asset("BNB.BNB")
        self.assertEqual(asset.to_json(), json.dumps("BNB.BNB"))
        asset = Asset("LOK-3C0")
        self.assertEqual(asset.to_json(), json.dumps("BNB.LOK-3C0"))
        asset = Asset("RUNE")
        self.assertEqual(asset.to_json(), json.dumps("BNB.RUNE"))


class TestCoin(unittest.TestCase):
    def test_constructor(self):
        coin = Coin("BNB.BNB", 100)
        self.assertEqual(coin.asset, "BNB.BNB")
        self.assertEqual(coin.amount, 100)
        coin = Coin("BNB")
        self.assertEqual(coin.asset, "BNB.BNB")
        self.assertEqual(coin.amount, 0)
        coin = Coin("RUNE-A1F", 1000000)
        self.assertEqual(coin.amount, 1000000)
        self.assertEqual(coin.asset, "BNB.RUNE-A1F")

    def test_is_zero(self):
        coin = Coin("BNB.BNB", 100)
        self.assertEqual(coin.is_zero(), False)
        coin = Coin("BNB")
        self.assertEqual(coin.is_zero(), True)
        coin = Coin("RUNE-A1F", 0)
        self.assertEqual(coin.is_zero(), True)

    def test_is_equal(self):
        coin1 = Coin("BNB.BNB", 100)
        coin2 = Coin("BNB")
        self.assertEqual(coin1.is_equal(coin2), False)
        coin1 = Coin("BNB.BNB", 100)
        coin2 = Coin("BNB", 100)
        self.assertEqual(coin1.is_equal(coin2), True)
        coin1 = Coin("BNB.LOK-3C0", 100)
        coin2 = Coin("RUNE-A1F", 100)
        self.assertEqual(coin1.is_equal(coin2), False)
        coin1 = Coin("BNB.LOK-3C0", 100)
        coin2 = Coin("BNB.LOK-3C0", 100)
        self.assertEqual(coin1.is_equal(coin2), True)
        coin1 = Coin("LOK-3C0", 200)
        coin2 = Coin("LOK-3C0", 200)
        self.assertEqual(coin1.is_equal(coin2), True)
        coin1 = Coin("RUNE")
        coin2 = Coin("RUNE")
        self.assertEqual(coin1.is_equal(coin2), True)

    def test_is_rune(self):
        coin = Coin("BNB.BNB")
        self.assertEqual(coin.is_rune(), False)
        coin = Coin("BNB.RUNE-A1F")
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
        self.assertEqual(str(coin), "0BNB.BNB")
        coin = Coin("RUNE", 1000000)
        self.assertEqual(str(coin), "1,000,000BNB.RUNE")
        coin = Coin("LOK-3C0", 1000000)
        self.assertEqual(str(coin), "1,000,000BNB.LOK-3C0")

    def test_repr(self):
        coin = Coin("BNB.BNB")
        self.assertEqual(repr(coin), "<Coin 0BNB.BNB>")
        coin = Coin("RUNE", 1000000)
        self.assertEqual(repr(coin), "<Coin 1,000,000BNB.RUNE>")
        coin = Coin("LOK-3C0", 1000000)
        self.assertEqual(repr(coin), "<Coin 1,000,000BNB.LOK-3C0>")

    def test_to_json(self):
        coin = Coin("BNB.BNB")
        self.assertEqual(coin.to_json(), '{"asset": "BNB.BNB", "amount": 0}')
        coin = Coin("RUNE", 1000000)
        self.assertEqual(coin.to_json(), '{"asset": "BNB.RUNE", "amount": 1000000}')
        coin = Coin("LOK-3C0", 1000000)
        self.assertEqual(coin.to_json(), '{"asset": "BNB.LOK-3C0", "amount": 1000000}')

class TestTransaction(unittest.TestCase):
    def test_constructor(self):
        txn = Transaction(
            Binance.chain,
            "USER",
            "VAULT",
            Coin("BNB.BNB", 100),
            "MEMO",
        )
        self.assertEqual(txn.chain, "BNB")
        self.assertEqual(txn.from_address, "USER")
        self.assertEqual(txn.to_address, "VAULT")
        self.assertEqual(txn.coins[0].asset, "BNB.BNB")
        self.assertEqual(txn.coins[0].amount, 100)
        self.assertEqual(txn.memo, "MEMO")
        txn.coins = [Coin("BNB", 1000000000), Coin("RUNE-A1F", 1000000000)]
        self.assertEqual(txn.coins[0].asset, "BNB.BNB")
        self.assertEqual(txn.coins[0].amount, 1000000000)
        self.assertEqual(txn.coins[1].asset, "BNB.RUNE-A1F")
        self.assertEqual(txn.coins[1].amount, 1000000000)

    def test_str(self):
        txn = Transaction(
            Binance.chain,
            "USER",
            "VAULT",
            Coin("BNB.BNB", 100),
            "MEMO",
        )
        self.assertEqual(str(txn), "Transaction USER ==> VAULT | 100BNB.BNB | MEMO")
        txn.coins = [Coin("BNB", 1000000000), Coin("RUNE-A1F", 1000000000)]
        self.assertEqual(str(txn), "Transaction USER ==> VAULT | 1,000,000,000BNB.BNB, 1,000,000,000BNB.RUNE-A1F | MEMO")

    def test_repr(self):
        txn = Transaction(
            Binance.chain,
            "USER",
            "VAULT",
            Coin("BNB.BNB", 100),
            "MEMO",
        )
        self.assertEqual(repr(txn), "<Transaction USER ==> VAULT | [<Coin 100BNB.BNB>] | MEMO>")
        txn.coins = [Coin("BNB", 1000000000), Coin("RUNE-A1F", 1000000000)]
        self.assertEqual(repr(txn), "<Transaction USER ==> VAULT | [<Coin 1,000,000,000BNB.BNB>, <Coin 1,000,000,000BNB.RUNE-A1F>] | MEMO>")

    def test_to_json(self):
        txn = Transaction(
            Binance.chain,
            "USER",
            "VAULT",
            Coin("BNB.BNB", 100),
            "STAKE:BNB",
        )
        self.assertEqual(txn.to_json(), '{"chain": "BNB", "from_address": "USER", "to_address": "VAULT", "memo": "STAKE:BNB", "coins": [{"asset": "BNB.BNB", "amount": 100}]}')
        txn.coins = [Coin("BNB", 1000000000), Coin("RUNE-A1F", 1000000000)]
        self.assertEqual(txn.to_json(), '{"chain": "BNB", "from_address": "USER", "to_address": "VAULT", "memo": "STAKE:BNB", "coins": [{"asset": "BNB.BNB", "amount": 1000000000}, {"asset": "BNB.RUNE-A1F", "amount": 1000000000}]}')
