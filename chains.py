import time
import logging
import base64
import hashlib

from common import Coin, Asset, HttpClient


class MockBinance(HttpClient):
    """
    An client implementation for a mock binance server
    https://gitlab.com/thorchain/bepswap/mock-binance
    """

    aliases = {
        "MASTER": "tbnb1ht7v08hv2lhtmk8y7szl2hjexqryc3hcldlztl",
        "CONTRIBUTOR-1": "tbnb1lltanv67yztkpt5czw4ajsmg94dlqnnhrq7zqm",
        "USER-1": "tbnb157dxmw9jz5emuf0apj4d6p3ee42ck0uwksxfff",
        "STAKER-1": "tbnb1mkymsmnqenxthlmaa9f60kd6wgr9yjy9h5mz6q",
        "STAKER-2": "tbnb189az9plcke2c00vns0zfmllfpfdw67dtv25kgx",
        "VAULT": "tbnb14jg77k8nwcz577zwd2gvdnpe2yy46j0hkvdvlg",
    }

    def set_vault_address(self, addr):
        """
        Set the vault bnb address
        """
        self.aliases["VAULT"] = addr

    def get_block_height(self):
        """
        Get the current block height of mock binance
        """
        data = self.fetch("/block")
        return int(data["result"]["block"]["header"]["height"])

    def get_block_tx(self, height):
        """
        Get the current block tx from height of mock binance
        """
        data = self.fetch(f"/block?height={height}")
        return data["result"]["block"]["data"]["txs"][0]

    def wait_for_blocks(self, count):
        """
        Wait for the given number of blocks
        """
        start_block = self.get_block_height()
        for x in range(0, 30):
            time.sleep(1)
            block = self.get_block_height()
            if block - start_block >= count:
                return
        raise Exception(f"failed waiting for mock binance transactions ({count})")

    def get_tx_id_from_block(self, height):
        """Get transaction hash ID from a block height.
        We first retrieve tx data from block then generate id from tx data:
        raw tx base 64 encoded -> base64 decode -> sha256sum = tx hash

        :param str height: block height
        :returns: tx hash id hex string

        """
        tx = self.get_block_tx(height)
        decoded = base64.b64decode(tx)
        return hashlib.new("sha256", decoded).digest().hex().upper()

    def accounts(self):
        return self.fetch("/accounts")

    def transfer(self, txn):
        """
        Make a transaction/transfer on mock binance
        """
        if not isinstance(txn.coins, list):
            txn.coins = [txn.coins]

        if txn.to_address in self.aliases:
            txn.to_address = self.aliases[txn.to_address]

        if txn.from_address in self.aliases:
            txn.from_address = self.aliases[txn.from_address]

        # update memo with actual address (over alias name)
        for name, addr in self.aliases.items():
            txn.memo = txn.memo.replace(name, addr)

        payload = {
            "from": txn.from_address,
            "to": txn.to_address,
            "memo": txn.memo,
            "coins": [coin.to_binance_fmt() for coin in txn.coins],
        }
        result = self.post("/broadcast/easy", payload)
        txn.id = self.get_tx_id_from_block(result["height"])


class Account:
    """
    An account is an address with a list of coin balances associated
    """

    def __init__(self, address):
        self.address = address
        self.balances = []

    def sub(self, coins):
        """
        Subtract coins from balance
        """
        if not isinstance(coins, list):
            coins = [coins]

        for coin in coins:
            for i, c in enumerate(self.balances):
                if coin.asset == c.asset:
                    self.balances[i].amount -= coin.amount
                    if self.balances[i].amount < 0:
                        logging.info(f"Balance: {self.address} {self.balances[i]}")
                        self.balances[i].amount = 0
                        # raise Exception("insufficient funds")

    def add(self, coins):
        """
        Add coins to balance
        """
        if not isinstance(coins, list):
            coins = [coins]

        for coin in coins:
            found = False
            for i, c in enumerate(self.balances):
                if coin.asset == c.asset:
                    self.balances[i].amount += coin.amount
                    found = True
                    break
            if not found:
                self.balances.append(coin)

    def get(self, asset):
        """
        Get a specific coin by asset
        """
        if isinstance(asset, str):
            asset = Asset(asset)
        for coin in self.balances:
            if asset == coin.asset:
                return coin.amount

        return 0

    def __repr__(self):
        return "<Account %s: %s>" % (self.address, self.balances)

    def __str__(self):
        return "Account %s: %s" % (self.address, self.balances)


class Binance:
    """
    A local simple implementation of binance chain
    """

    chain = "BNB"

    def __init__(self):
        self.accounts = {}

    def _calculate_gas(self, coins):
        """
        With given coin set, calculates the gas owed
        """
        if not isinstance(coins, list) or len(coins) == 1:
            return Coin("BNB", 37500)
        return Coin("BNB", 30000 * len(coins))

    def get_account(self, addr):
        """
        Retrieve an accout by address
        """
        if addr in self.accounts:
            return self.accounts[addr]
        return Account(addr)

    def set_account(self, acct):
        """
        Update a given account
        """
        self.accounts[acct.address] = acct

    def transfer(self, txn):
        """
        Makes a transfer on the binance chain. Returns gas used
        """

        if txn.chain != Binance.chain:
            raise Exception(f"Cannot transfer. {Binance.chain} is not {txn.chain}")

        from_acct = self.get_account(txn.from_address)
        to_acct = self.get_account(txn.to_address)

        gas = self._calculate_gas(txn.coins)
        from_acct.sub(gas)

        from_acct.sub(txn.coins)
        to_acct.add(txn.coins)

        self.set_account(from_acct)
        self.set_account(to_acct)

        txn.gas = [gas]
