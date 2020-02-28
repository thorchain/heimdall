import requests
import json

from collections import MutableMapping
from contextlib import suppress
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from exceptions import CoinError, TransactionError


def requests_retry_session(
    retries=6, backoff_factor=1, status_forcelist=(500, 502, 504), session=None,
):
    """
    Creates a request session that has auto retry
    """
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def get_share(part, total, alloc):
    """
    Calculates the share of something
    (Allocation / (Total / part))
    """
    return float(alloc) / (float(total) / float(part))


def delete_keys_from_dict(dictionary, keys):
    """
    Delete values from dict if key in keys
    """
    for key in keys:
        with suppress(KeyError):
            del dictionary[key]
    for value in dictionary.values():
        if isinstance(value, MutableMapping):
            delete_keys_from_dict(value, keys)


class HttpClient:
    """
    An generic http client
    """

    def __init__(self, base_url):
        self.base_url = base_url

    def get_url(self, path):
        """
        Get fully qualified url with given path
        """
        return self.base_url + path

    def fetch(self, path, args={}):
        """
        Make a get request
        """
        url = self.get_url(path)
        resp = requests_retry_session().get(url, params=args)
        resp.raise_for_status()
        return resp.json()

    def post(self, path, payload={}):
        """
        Make a post request
        """
        url = self.get_url(path)
        resp = requests_retry_session().post(url, json=payload)
        resp.raise_for_status()
        return resp.json()


class Jsonable:
    def to_json(self):
        return json.dumps(self, default=lambda x: x.__dict__)


class Asset(str, Jsonable):
    def __new__(cls, value, *args, **kwargs):
        if len(value.split(".")) < 2:
            value = f"BNB.{value}"  # default to binance chain
        return super().__new__(cls, value)

    def is_rune(self):
        """
        Is this asset rune?
        """
        return self.get_symbol().startswith("RUNE")

    def get_symbol(self):
        """
        Return symbol part of the asset string
        """
        return self.split(".")[1]

    def get_chain(self):
        """
        Return chain part of the asset string
        """
        return self.split(".")[0]


class Coin(Jsonable):
    """
    A class that represents a coin and an amount
    """

    def __init__(self, asset, amount=0):
        self.asset = Asset(asset)
        self.amount = int(amount)

    def is_rune(self):
        """
        Is this coin rune?
        """
        return self.asset.is_rune()

    def is_zero(self):
        """
        Is the amount of this coin zero?
        """
        return self.amount == 0

    def to_binance_fmt(self):
        """
        Convert the class to an dictionary, specifically in a format for
        mock-binance
        """
        return {
            "denom": self.asset.get_symbol(),
            "amount": self.amount,
        }

    def is_equal(self, coin):
        """
        Does this coin equal another?
        """
        if self.asset != coin.asset or self.amount != coin.amount:
            raise CoinError(f"Coin mismatch {self} != {coin}")
        return True

    @classmethod
    def coins_equal(cls, coins1, coins2):
        """
        Compare 2 coins list
        """
        coins1 = coins1 or []
        coins2 = coins2 or []
        if len(coins1) != len(coins2):
            raise CoinError(
                f"Coins list length mismatch {len(coins1)} != {len(coins2)}"
            )
        for coin1, coin2 in zip(coins1, coins2):
            coin1.is_equal(coin2)
        return True

    @classmethod
    def from_dict(cls, value):
        return cls(value["asset"], value["amount"])

    def __repr__(self):
        return f"<Coin {self.amount:0,.0f}{self.asset}>"

    def __str__(self):
        return f"{self.amount:0,.0f}{self.asset}"


class Transaction(Jsonable):
    """
    A transaction on a block chain (ie Binance)
    """

    def __init__(self, chain, from_address, to_address, coins, memo="", gas=None):
        self.chain = chain
        self.from_address = from_address
        self.to_address = to_address
        self.memo = memo

        # ensure coins is a list of coins
        if coins and not isinstance(coins, list):
            coins = [coins]
        self.coins = coins

        # ensure gas is a list of coins
        if gas and not isinstance(gas, list):
            gas = [gas]
        self.gas = gas

    def __repr__(self):
        coins = self.coins if self.coins else "No Coins"
        gas = f" | Gas {self.gas}" if self.gas else ""
        return (
            f"<Transaction {self.from_address} ==> {self.to_address} | "
            f"{coins} | {self.memo}{gas}>"
        )

    def __str__(self):
        coins = ", ".join([str(c) for c in self.coins]) if self.coins else "No Coins"
        gas = " | Gas " + ", ".join([str(g) for g in self.gas]) if self.gas else ""
        return (
            f"Transaction {self.from_address} ==> {self.to_address} | "
            f"{coins} | {self.memo}{gas}"
        )

    def is_equal(self, txn, strict=True):
        """
        Does this txn equal another?
        """
        try:
            if self.chain != txn.chain:
                raise TransactionError(f"Chain mismatch {self.chain} != {txn.chain}")
            Coin.coins_equal(self.coins, txn.coins)
            if strict:
                if self.memo != txn.memo:
                    raise TransactionError(f"Memo mismatch {self.memo} != {txn.memo}")
                Coin.coins_equal(self.gas, txn.gas)
                if self.from_address == txn.from_address:
                    raise TransactionError(
                        f"From address mismatch {self.from_address} != "
                        f"{txn.from_address}"
                    )
                if self.to_address == txn.to_address:
                    raise TransactionError(
                        f"To address mismatch {self.to_address} != {txn.to_address}"
                    )
        except Exception as e:
            raise TransactionError(f"Transaction mismatch {self} != {txn} \n {e}")
        else:
            return True

    @classmethod
    def txns_equal(cls, txns1, txns2, strict=True):
        """
        Compare 2 txns list
        """
        txns1 = txns1 or []
        txns2 = txns2 or []
        if len(txns1) != len(txns2):
            raise TransactionError(
                f"Transactions list length mismatch {len(txns1)} != {len(txns2)}"
            )
        for txn1, txn2 in zip(txns1, txns2):
            txn1.is_equal(txn2, strict=strict)
        return True

    @classmethod
    def from_dict(cls, value):
        txn = cls(
            value["chain"],
            value["from_address"],
            value["to_address"],
            None,
            memo=value["memo"],
        )
        if "coins" in value and value["coins"]:
            txn.coins = [Coin.from_dict(c) for c in value["coins"]]
        if "gas" in value and value["gas"]:
            txn.gas = [Coin.from_dict(g) for g in value["gas"]]
        return txn

    @classmethod
    def empty_txn(self):
        return Transaction("", "", "", None)
