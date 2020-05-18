import time
import logging
import json
import requests

from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from eth_keys import KeyAPI
from utils.common import Coin, get_rune_asset
from chains.aliases import aliases_eth, get_aliases, get_alias_address
from chains.account import Account

RUNE = get_rune_asset()


def calculate_gas(msg):
    return MockEthereum.default_gas + MockEthereum.gas_per_byte * len(msg)


class MockEthereum:
    """
    An client implementation for a localnet/rinkebye/ropston Ethereum server
    """

    default_gas = 21000
    gas_per_byte = 68
    gas_price = 1
    passphrase = "the-passphrase"

    private_keys = [
        "ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2",
        "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032",
        "e810f1d7d6691b4a7a73476f3543bd87d601f9a53e7faf670eac2c5b517d83bf",
        "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
        "9294f4d108465fd293f7fe299e6923ef71a77f2cb1eb6d4394839c64ec25d5c0",
    ]

    def __init__(self, base_url):
        self.url = base_url
        for key in self.private_keys:
            payload = json.dumps(
                {"method": "personal_importRawKey", "params": [key, self.passphrase]}
            )
            headers = {"content-type": "application/json", "cache-control": "no-cache"}
            try:
                requests.request("POST", base_url, data=payload, headers=headers)
            except requests.exceptions.RequestException as e:
                logging.error(f"{e}")
        self.web3 = Web3(HTTPProvider(base_url))
        self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    @classmethod
    def get_address_from_pubkey(cls, pubkey):
        """
        Get Ethereum address for a specific hrp (human readable part)
        bech32 encoded from a public key(secp256k1).

        :param string pubkey: public key
        :returns: string 0x encoded address
        """
        eth_pubkey = KeyAPI.PublicKey.from_compressed_bytes(pubkey)
        return eth_pubkey.to_address()

    def set_vault_address(self, addr):
        """
        Set the vault eth address
        """
        aliases_eth["VAULT"] = addr

    def get_block_height(self):
        """
        Get the current block height of Ethereum localnet
        """
        block = self.web3.eth.getBlock("latest")
        return block["number"]

    def get_block_hash(self, block_height):
        """
        Get the block hash for a height
        """
        block = self.web3.eth.getBlock(block_height)
        return block["hash"].hex()

    def set_block(self, block_height):
        """
        Set head for reorg
        """
        payload = json.dumps({"method": "debug_setHead", "params": [block_height]})
        headers = {"content-type": "application/json", "cache-control": "no-cache"}
        try:
            requests.request("POST", self.url, data=payload, headers=headers)
        except requests.exceptions.RequestException as e:
            logging.error(f"{e}")

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

    def get_balance(self, address):
        """
        Get ETH balance for an address
        """
        return self.web3.eth.getBalance(Web3.toChecksumAddress(address), "latest")

    def wait_for_node(self):
        """
        Ethereum localnet node is started with directly mining 100 blocks
        to be able to start handling transactions.
        It can take a while depending on the machine specs so we retry.
        """
        current_height = self.get_block_height()
        while current_height < 4:
            current_height = self.get_block_height()

    def transfer(self, txn):
        """
        Make a transaction/transfer on localnet Ethereum
        """
        if not isinstance(txn.coins, list):
            txn.coins = [txn.coins]

        if txn.to_address in get_aliases():
            txn.to_address = get_alias_address(txn.chain, txn.to_address)

        if txn.from_address in get_aliases():
            txn.from_address = get_alias_address(txn.chain, txn.from_address)

        # update memo with actual address (over alias name)
        for alias in get_aliases():
            chain = txn.chain
            asset = txn.get_asset_from_memo()
            if asset:
                chain = asset.get_chain()
            # we use RUNE BNB address to identify a cross chain stake
            if txn.memo.startswith("STAKE"):
                chain = RUNE.split(".")[0]
            addr = get_alias_address(chain, alias)
            txn.memo = txn.memo.replace(alias, addr)

        # create and send transaction
        tx = {
            "from": Web3.toChecksumAddress(txn.from_address),
            "to": Web3.toChecksumAddress(txn.to_address),
            "value": txn.coins[0].amount,
            "data": "0x" + txn.memo.encode().hex(),
            "gas": calculate_gas(txn.memo),
        }

        tx_hash = self.web3.geth.personal.send_transaction(tx, self.passphrase)
        receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        txn.id = receipt["transactionHash"].hex()[2:]
        txn.gas = [Coin("ETH.ETH", receipt["cumulativeGasUsed"] * self.gas_price)]


class Ethereum:
    """
    A local simple implementation of Ethereum chain
    """

    chain = "ETH"

    def __init__(self):
        self.accounts = {}

    @classmethod
    def calculate_gas(cls, pool, rune_fee):
        """
        Calculate gas according to RUNE thorchain fee
        1 RUNE / 2 in ETH value
        """
        return Coin("ETH.ETH", calculate_gas("") * MockEthereum.gas_price)

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
        Makes a transfer on the Ethereum chain. Returns gas used
        """

        if txn.chain != Ethereum.chain:
            raise Exception(f"Cannot transfer. {Ethereum.chain} is not {txn.chain}")

        from_acct = self.get_account(txn.from_address)
        to_acct = self.get_account(txn.to_address)

        if not txn.gas:
            txn.gas = [
                Coin("ETH.ETH", calculate_gas(txn.memo) * MockEthereum.gas_price)
            ]

        from_acct.sub(txn.gas[0])
        from_acct.sub(txn.coins)
        to_acct.add(txn.coins)

        self.set_account(from_acct)
        self.set_account(to_acct)

        return txn.gas[0]
