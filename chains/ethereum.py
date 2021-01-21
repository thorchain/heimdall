import logging
import json
import requests

from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from eth_keys import KeyAPI
from utils.common import Coin, get_rune_asset, Asset
from chains.aliases import aliases_eth, get_aliases, get_alias_address
from chains.chain import GenericChain

RUNE = get_rune_asset()


def calculate_gas(msg):
    return MockEthereum.default_gas + Ethereum.gas_per_byte * len(msg)


class MockEthereum:
    """
    An client implementation for a localnet/rinkebye/ropston Ethereum server
    """

    default_gas = 80000
    gas_price = 1
    passphrase = "the-passphrase"
    seed = "SEED"
    stake = "ADD"
    tokens = dict()
    zero_address = "0x0000000000000000000000000000000000000000"
    vault_contract_addr = "0xE65e9d372F8cAcc7b6dfcd4af6507851Ed31bb44"
    token_contract_addr = "0x40bcd4dB8889a8Bf0b1391d0c819dcd9627f9d0a"

    private_keys = [
        "ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2",
        "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032",
        "e810f1d7d6691b4a7a73476f3543bd87d601f9a53e7faf670eac2c5b517d83bf",
        "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
        "9294f4d108465fd293f7fe299e6923ef71a77f2cb1eb6d4394839c64ec25d5c0",
    ]

    def __init__(self, base_url):
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
        self.vault = self.get_vault()
        token = self.get_token()
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

    def get_block_height(self):
        """
        Get the current block height of Ethereum localnet
        """
        block = self.web3.eth.getBlock("latest")
        return block["number"]

    def get_token(self):
        abi = json.load(open("data/token.json"))
        token = self.web3.eth.contract(address=self.token_contract_addr, abi=abi)
        return token

    def get_vault(self):
        abi = json.load(open("data/vault.json"))
        vault = self.web3.eth.contract(address=self.vault_contract_addr, abi=abi)
        return vault

    def get_block_hash(self, block_height):
        """
        Get the block hash for a height
        """
        block = self.web3.eth.getBlock(block_height)
        return block["hash"].hex()

    def get_block_stats(self, block_height=None):
        """
        Get the block hash for a height
        """
        return {
            "avg_tx_size": 1,
            "avg_fee_rate": 1,
        }

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
            # we use RUNE BNB address to identify a cross chain liqudity provision
            if txn.memo.startswith(self.stake):
                chain = RUNE.get_chain()
            addr = get_alias_address(chain, alias)
            txn.memo = txn.memo.replace(alias, addr)

        for account in self.web3.eth.accounts:
            if account.lower() == txn.from_address.lower():
                self.web3.geth.personal.unlock_account(account, self.passphrase)
                self.web3.eth.defaultAccount = account

        spent_gas = 0
        if txn.memo == self.seed:

            if txn.coins[0].asset.get_symbol() == Ethereum.chain:
                tx_hash = self.vault.functions.deposit(
                    Web3.toChecksumAddress(txn.to_address),
                    Web3.toChecksumAddress(self.zero_address),
                    0,
                    txn.memo,
                ).transact(
                    {
                        "value": txn.coins[0].amount,
                        "gas": calculate_gas(txn.memo),
                    }
                )
            else:
                tx_hash = (
                    self.tokens[txn.coins[0].asset.get_symbol().split("-")[0]]
                    .functions.transfer(
                        Web3.toChecksumAddress(txn.to_address), txn.coins[0].amount
                    )
                    .transact()
                )
        else:
            memo = txn.memo

            if txn.coins[0].asset.get_symbol().split("-")[0] == Ethereum.chain:
                tx_hash = self.vault.functions.deposit(
                    Web3.toChecksumAddress(txn.to_address),
                    Web3.toChecksumAddress(self.zero_address),
                    0,
                    txn.memo,
                ).transact({"value": txn.coins[0].amount})
            else:
                # approve the tx first
                symbol = txn.coins[0].asset.get_symbol().split("-")[0]
                tx_hash = (
                    self.tokens[symbol]
                    .functions.approve(
                        Web3.toChecksumAddress(self.vault.address), txn.coins[0].amount
                    )
                    .transact()
                )
                token_address = self.tokens[symbol].address
                receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
                spent_gas = receipt.cumulativeGasUsed
                tx_hash = self.vault.functions.deposit(
                    Web3.toChecksumAddress(txn.to_address),
                    token_address,
                    txn.coins[0].amount,
                    memo.encode("utf-8"),
                ).transact()

        receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        txn.id = receipt.transactionHash.hex()[2:].upper()
        txn.gas = [
            Coin(
                "ETH.ETH",
                (receipt.gasUsed + spent_gas) * self.gas_price,
            )
        ]


class Ethereum(GenericChain):
    """
    A local simple implementation of Ethereum chain
    """

    name = "Ethereum"
    gas_per_byte = 68
    chain = "ETH"
    coin = Asset("ETH.ETH")
    withdrawals = {}
    swaps = {}

    @classmethod
    def _calculate_gas(cls, pool, txn):
        """
        Calculate gas according to RUNE thorchain fee
        """
        gas = 39540
        if txn.gas is not None and txn.gas[0].asset.is_eth():
            gas = txn.gas[0].amount
        if txn.memo == "WITHDRAW:ETH.ETH:1000":
            gas = 35617
        elif txn.memo.startswith("SWAP:ETH.ETH:"):
            gas = 35605
        elif txn.memo.startswith(
            "SWAP:ETH.TKN-0X40BCD4DB8889A8BF0B1391D0C819DCD9627F9D0A"
        ):
            gas = 53743
        elif (
            txn.memo
            == "WITHDRAW:ETH.TKN-0X40BCD4DB8889A8BF0B1391D0C819DCD9627F9D0A:1000"
        ):
            gas = 53755
        elif txn.memo == "WITHDRAW:ETH.TKN-0X40BCD4DB8889A8BF0B1391D0C819DCD9627F9D0A":
            gas = 26872
        elif txn.memo == "WITHDRAW:ETH.ETH":
            gas = 35617
        return Coin(cls.coin, gas * MockEthereum.gas_price)
