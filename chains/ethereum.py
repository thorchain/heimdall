import time
import logging
import json
import requests

from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from solcx import compile_files, install_solc
from eth_keys import KeyAPI
from eth_utils import keccak
from utils.common import Coin, get_rune_asset, Asset
from chains.aliases import aliases_eth, get_aliases, get_alias_address
from chains.chain import GenericChain

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
    zero_address = "ETH-0X0000000000000000000000000000000000000000"
    seed = "SEED"
    stake = "STAKE"
    eth = "ETH."
    tokens = dict()

    private_keys = [
        "ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2",
        "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032",
        "e810f1d7d6691b4a7a73476f3543bd87d601f9a53e7faf670eac2c5b517d83bf",
        "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
        "9294f4d108465fd293f7fe299e6923ef71a77f2cb1eb6d4394839c64ec25d5c0",
    ]

    def __init__(self, base_url, eth_address):
        self.url = base_url
        self.web3 = Web3(HTTPProvider(base_url))
        self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        for key in self.private_keys:
            payload = json.dumps(
                {"method": "personal_importRawKey", "params": [key, self.passphrase]}
            )
            headers = {"content-type": "application/json", "cache-control": "no-cache"}
            try:
                requests.request("POST", base_url, data=payload, headers=headers)
            except requests.exceptions.RequestException as e:
                logging.error(f"{e}")
        self.accounts = self.web3.geth.personal.list_accounts()
        self.web3.eth.defaultAccount = self.accounts[1]
        self.web3.geth.personal.unlock_account(
            self.web3.eth.defaultAccount, self.passphrase
        )
        self.vault = self.deploy_vault()
        token = self.deploy_token()
        symbol = token.functions.symbol().call()
        self.tokens[symbol] = token

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
        tx_hash = self.vault.functions.addAsgard(
            Web3.toChecksumAddress(addr)
        ).transact()
        receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)

    def get_block_height(self):
        """
        Get the current block height of Ethereum localnet
        """
        block = self.web3.eth.getBlock("latest")
        return block["number"]

    def deploy_token(self):
        abi = json.load(open("data/token.json"))
        bytecode = open("data/token.txt", "r").read()
        token = self.web3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = token.constructor().transact()
        receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        return self.web3.eth.contract(address=receipt.contractAddress, abi=abi)

    def deploy_vault(self):
        abi = json.load(open("data/vault.json"))
        bytecode = open("data/vault.txt", "r").read()
        vault = self.web3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = vault.constructor().transact()
        receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        return self.web3.eth.contract(address=receipt.contractAddress, abi=abi)

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

    def get_balance(self, address, symbol):
        """
        Get ETH or token balance for an address
        """
        if symbol == "ETH":
            return self.web3.eth.getBalance(Web3.toChecksumAddress(address), "latest")

        if address == "VAULT" or address == aliases_eth["VAULT"]:
            address = self.vault.address

        return (
            self.tokens[symbol]
            .functions.balanceOf(Web3.toChecksumAddress(address))
            .call()
        )

    def wait_for_node(self):
        """
        Ethereum pow localnet node is started with directly mining 4 blocks
        to be able to start handling transactions.
        It can take a while depending on the machine specs so we retry.
        """
        current_height = self.get_block_height()
        while current_height < 2:
            current_height = self.get_block_height()

    def transfer(self, txn):
        """
        Make a transaction/transfer on localnet Ethereum
        """
        if not isinstance(txn.coins, list):
            txn.coins = [txn.coins]

        if txn.to_address in aliases_eth.keys():
            txn.to_address = get_alias_address(txn.chain, txn.to_address)

        if txn.from_address in aliases_eth.keys():
            txn.from_address = get_alias_address(txn.chain, txn.from_address)

        # update memo with actual address (over alias name)
        for alias in get_aliases():
            chain = txn.chain
            asset = txn.get_asset_from_memo()
            if asset:
                chain = asset.get_chain()
            # we use RUNE BNB address to identify a cross chain stake
            if txn.memo.startswith(self.stake):
                chain = RUNE.get_chain()
            addr = get_alias_address(chain, alias)
            txn.memo = txn.memo.replace(alias, addr)

        for account in self.web3.eth.accounts:
            if account == Web3.toChecksumAddress(txn.from_address):
                self.web3.geth.personal.unlock_account(account, self.passphrase)
                self.web3.eth.defaultAccount = account

        spent_gas = 0
        if txn.memo == self.seed:
            if txn.coins[0].asset.get_symbol() == self.zero_address:
                tx = {
                    "from": Web3.toChecksumAddress(txn.from_address),
                    "to": Web3.toChecksumAddress(txn.to_address),
                    "value": txn.coins[0].amount,
                    "data": "0x" + txn.memo.encode().hex(),
                    "gas": calculate_gas(txn.memo),
                }
                tx_hash = self.web3.geth.personal.send_transaction(tx, self.passphrase)
            else:
                tx_hash = (
                    self.tokens[txn.coins[0].asset.get_symbol().split("-")[0]]
                    .functions.transfer(
                        Web3.toChecksumAddress(txn.to_address), txn.coins[0].amount
                    )
                    .transact()
                )
        else:
            value = 0
            if txn.coins[0].asset.get_symbol() == self.zero_address:
                value = txn.coins[0].amount
            else:
                tx_hash = (
                    self.tokens[txn.coins[0].asset.get_symbol().split("-")[0]]
                    .functions.approve(
                        Web3.toChecksumAddress(self.vault.address), txn.coins[0].amount
                    )
                    .transact()
                )
                receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
                spent_gas = receipt.cumulativeGasUsed
            if txn.memo.find(":ETH.") != -1:
                splits = txn.coins[0].asset.get_symbol().split("-")
                parts = txn.memo.split("-")
                if len(parts) != 2 or len(splits) != 2:
                    logging.error(f"incorrect ETH txn memo")
                ps = parts[1].split(":")
                if len(ps) != 2:
                    logging.error(f"incorrect ETH txn memo")
                memo = parts[0] + ":" + ps[1]
            else:
                memo = txn.memo
            tx_hash = self.vault.functions.deposit(
                Web3.toChecksumAddress(txn.coins[0].asset.get_symbol().split("-")[1]),
                Web3.toChecksumAddress(aliases_eth["VAULT"]),
                txn.coins[0].amount,
                memo.encode("utf-8"),
            ).transact({"value": value})

        receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        tx_full = self.web3.eth.getTransaction(tx_hash.hex())
        txn.id = receipt.transactionHash.hex()[2:].upper()
        txn.gas = [
            Coin(
                "ETH.ETH-0X0000000000000000000000000000000000000000",
                (receipt.cumulativeGasUsed + spent_gas) * self.gas_price,
            )
        ]


class Ethereum(GenericChain):
    """
    A local simple implementation of Ethereum chain
    """

    name = "Ethereum"
    chain = "ETH"
    coin = Asset("ETH.ETH-0X0000000000000000000000000000000000000000")

    @classmethod
    def _calculate_gas(cls, pool, txn):
        """
        Calculate gas according to RUNE thorchain fee
        1 RUNE / 2 in ETH value
        """
        gas = 21000
        if txn.memo.startswith("WITHDRAW") and txn.memo.find("ETH.ETH") == -1:
            gas = 47997
        if txn.memo.startswith("SWAP:ETH.") and txn.memo.find("ETH.ETH") == -1:
            gas = 47933
        return Coin(cls.coin, gas * MockEthereum.gas_price)
