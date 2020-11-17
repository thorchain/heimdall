import requests
import logging
import json
import os
import hashlib

from decimal import Decimal, getcontext

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

DEFAULT_RUNE_ASSET = "BNB.RUNE-67C"


def get_rune_asset():
    return Asset(os.environ.get("RUNE", DEFAULT_RUNE_ASSET))


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
    if total == 0 or part == 0:
        return 0
    getcontext().prec = 18
    return int(round(Decimal(alloc) / (Decimal(total) / Decimal(part))))


def get_diff(current, previous):
    if current == previous:
        return 0
    try:
        return (abs(current - previous) / ((current + previous) / 2)) * 100.0
    except ZeroDivisionError:
        return float("inf")


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
        if resp.status_code != 200:
            logging.error(resp.text)
        resp.raise_for_status()
        return json.loads(resp.text, parse_float=Decimal)


class Jsonable:
    def to_json(self):
        return json.dumps(self, default=lambda x: x.__dict__)


class Asset(str, Jsonable):
    def __new__(cls, value, *args, **kwargs):
        if len(value.split(".")) < 2:
            value = f"THOR.{value}"  # default to thorchain
        return super().__new__(cls, value)

    def is_bnb(self):
        """
        Is this asset bnb?
        """
        return self.get_symbol().startswith("BNB")

    def is_btc(self):
        """
        Is this asset btc?
        """
        return self.get_symbol().startswith("BTC")

    def is_eth(self):
        """
        Is this asset eth?
        """
        return self.get_symbol().startswith("ETH")

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

    ONE = 100000000

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

    def to_thorchain_fmt(self):
        """
        Convert the class to an dictionary, specifically in a format for
        thorchain
        """
        return {
            "asset": self.asset,
            "amount": str(self.amount),
        }

    def to_binance_fmt(self):
        """
        Convert the class to an dictionary, specifically in a format for
        mock-binance
        """
        return {
            "denom": self.asset.get_symbol(),
            "amount": self.amount,
        }

    def __eq__(self, other):
        return self.asset == other.asset and self.amount == other.amount

    def __lt__(self, other):
        return self.amount < other.amount

    def __sub__(self, other):
        return self.amount - other.amount

    def __add__(self, other):
        return self.amount + other.amount

    def __hash__(self):
        return hash(str(self))

    @classmethod
    def from_dict(cls, value):
        return cls(value["asset"], value["amount"])

    def __repr__(self):
        return f"<Coin {self.amount:0,.0f}_{self.asset}>"

    def __str__(self):
        return f"{self.amount:0,.0f}_{self.asset}"

    def str_amt(self):
        return f"{self.amount:0,.0f}"


class Transaction(Jsonable):
    """
    A transaction on a block chain (ie Binance)
    """

    empty_id = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(
        self, chain, from_address, to_address, coins, memo="", gas=None, id="TODO"
    ):
        self.id = id.upper()
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
        self.fee = None

    def __repr__(self):
        coins = self.coins if self.coins else "No Coins"
        gas = f" | Gas {self.gas}" if self.gas else ""
        fee = f" | Fee {self.fee}" if self.fee else ""
        id = f" | ID {self.id.upper()}" if self.id != "TODO" else ""
        return (
            f"<Tx {self.from_address:>8} => {self.to_address:8} | "
            f"{self.memo} | {coins}{gas}{fee}{id}>"
        )

    def __str__(self):
        coins = ", ".join([str(c) for c in self.coins]) if self.coins else "No Coins"
        gas = " | Gas " + ", ".join([str(g) for g in self.gas]) if self.gas else ""
        fee = f" | Fee {str(self.fee)}" if self.fee else ""
        id = (
            f" | ID {self.id.upper()}"
            if self.id != "TODO" and self.id != self.empty_id
            else ""
        )
        return (
            f"Tx {self.from_address:>8} => {self.to_address:8} | "
            f"{self.memo} | {coins}{gas}{fee}{id}"
        )

    def short(self):
        coins = ", ".join([str(c) for c in self.coins]) if self.coins else "No Coins"
        gas = ", ".join([str(g) for g in self.gas]) if self.gas else ""
        fee = str(self.fee) if self.fee else ""
        return f"{coins} | Fee {fee} | Gas {gas}"

    def __eq__(self, other):
        """
        Check transaction equals another one
        Ignore from to address fields because our thorchain state
        doesn't know the "real" addresses yet
        """
        coins = self.coins or []
        other_coins = other.coins or []
        gas = self.gas or []
        other_gas = other.gas or []
        return (
            (
                self.id == "TODO"
                or self.id == self.empty_id
                or self.id.upper() == other.id.upper()
            )
            and self.chain == other.chain
            and self.memo == other.memo
            and self.from_address == other.from_address
            and self.to_address == other.to_address
            and sorted(coins) == sorted(other_coins)
            and sorted(gas) == sorted(other_gas)
        )

    def __lt__(self, other):
        coins = self.coins or []
        other_coins = other.coins or []
        return sorted(coins) < sorted(other_coins)

    def get_asset_from_memo(self):
        parts = self.memo.split(":")
        if len(parts) >= 2 and parts[1] != "":
            return Asset(parts[1])
        return None

    def is_cross_chain_provision(self):
        if not self.memo.startswith("ADD:"):
            return False
        return True

    def custom_hash(self, pubkey):
        coins = (
            ", ".join([f"{c.amount} {c.asset}" for c in self.coins])
            if self.coins
            else ""
        )
        in_hash = self.memo.split(":")[1]
        tmp = f"{self.chain}|{self.to_address}|{pubkey}|{coins}||{in_hash}"
        return hashlib.new("sha256", tmp.encode()).digest().hex().upper()

    def get_attributes(self):
        return [
            {"id": self.id},
            {"chain": self.chain},
            {"from": self.from_address},
            {"to": self.to_address},
            {"coin": self.coins_str()},
            {"memo": self.memo},
        ]

    def coins_str(self):
        return ", ".join([f"{c.amount} {c.asset}" for c in self.coins])

    @classmethod
    def from_dict(cls, value):
        txn = cls(
            value["chain"],
            value["from_address"],
            value["to_address"],
            None,
            memo=value["memo"],
        )
        if "id" in value and value["id"]:
            txn.id = value["id"].upper()
        if "coins" in value and value["coins"]:
            txn.coins = [Coin.from_dict(c) for c in value["coins"]]
        if "gas" in value and value["gas"]:
            txn.gas = [Coin.from_dict(g) for g in value["gas"]]
        return txn

    @classmethod
    def empty_txn(cls):
        return Transaction("", "", "", None, id=cls.empty_id)
