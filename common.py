import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

def requests_retry_session(
    retries=6,
    backoff_factor=1,
    status_forcelist=(500, 502, 504),
    session=None,
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
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def get_share(part, total, alloc):
    """
    Calculates the share of something
    (Allocation / (Total / part))
    """
    return float(alloc) / (float(total) / float(part))


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


class Asset:
    def __init__(self, asset_str):
        parts = asset_str.split(".")
        if len(parts) < 2:
            self.chain = "BNB" # default to binance chain
            self.symbol = parts[0]
        else:
            self.chain = parts[0]
            self.symbol = parts[1]

    def is_rune(self):
        """
        Is this asset rune?
        """
        return self.symbol.startswith("RUNE")

    def is_equal(self, asset):
        """
        Is this asset equal to given asset?
        """
        if isinstance(asset, str):
            asset = Asset(asset)
        return self.chain == asset.chain and self.symbol == asset.symbol

    def __repr__(self):
        return "<Asset %s.%s>" % (self.chain, self.symbol)

    def __str__(self):
        return "%s.%s" % (self.chain, self.symbol)


class Coin:
    """
    A class that represents a coin and an amount
    """
    def __init__(self, asset, amount):
        self.asset = asset
        if isinstance(asset, str):
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
        return self.asset.is_equal(coin.asset) and self.amount == coin.amount

    def to_dict(self):
        """
        Convert the class to an dictionary, specifically in a format for
        mock-binance
        """
        return {
            "denom": self.asset.symbol,
            "amount": self.amount,
        }

    def __repr__(self):
        return "<Coin %d%s>" % ((self.amount), self.asset)

    def __str__(self):
        return "%d%s" % ((self.amount), self.asset)


class Transaction:
    """
    A transaction on a block chain (ie Binance)
    """
    def __init__(self, _chain, _from, _to, _coins, _memo = ""):
        self.chain = _chain
        self.toAddress = _to
        self.fromAddress = _from
        self.memo = _memo

        # ensure coins is a list of coins
        if not isinstance(_coins, list):
            _coins = [_coins]
        self.coins = _coins

    def __repr__(self):
        return "<Transaction %s ==> %s | %s | %s>" % (self.fromAddress, self.toAddress, self.coins, self.memo)

    def __str__(self):
        return "Transaction %s ==> %s | %s | %s" % (self.fromAddress, self.toAddress, self.coins, self.memo)
