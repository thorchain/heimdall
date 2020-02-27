import requests
import json

from collections import MutableMapping
from contextlib import suppress
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


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


class Asset(str):
    def __new__(cls, value, *args, **kwargs):
        if len(value.split(".")) < 2:
            value = f"BNB.{value}"  # default to binance chain
        return super().__new__(cls, value)

    def is_rune(self):
        """
        Is this asset rune?
        """
        return self == "BNB.RUNE-A1F"

    def get_symbol(self):
        """
        Return symbol part of the asset string
        """
        return self.split(".")[1]


class Coin(Jsonable):
    """
    A class that represents a coin and an amount
    """

    def __init__(self, asset, amount):
        self.asset = Asset(asset)
        self.amount = amount

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

    def is_equal(self, coin):
        """
        Does this coin equal another?
        """
        return self.asset == coin.asset and self.amount == coin.amount

    def to_binance_fmt(self):
        """
        Convert the class to an dictionary, specifically in a format for
        mock-binance
        """
        return {
            "denom": self.asset.get_symbol(),
            "amount": self.amount,
        }

    def __repr__(self):
        return f"<Coin {self.amount}{self.asset}>"

    def __str__(self):
        return f"{self.amount}{self.asset}"


class Transaction(Jsonable):
    """
    A transaction on a block chain (ie Binance)
    """

    def __init__(self, _chain, _from, _to, _coins, _memo=""):
        self.chain = _chain
        self.to_address = _to
        self.from_address = _from
        self.memo = _memo

        # ensure coins is a list of coins
        if not isinstance(_coins, list):
            _coins = [_coins]
        self.coins = _coins

    def __repr__(self):
        return "<Transaction %s ==> %s | %s | %s>" % (
            self.from_address,
            self.to_address,
            self.coins,
            self.memo,
        )

    def __str__(self):
        return "Transaction %s ==> %s | %s | %s" % (
            self.from_address,
            self.to_address,
            self.coins,
            self.memo,
        )
