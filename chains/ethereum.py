import time
import logging

from web3 import Web3, HTTPProvider
from eth_keys import KeyAPI     
from common import Coin
from decimal import Decimal, getcontext
from chains.aliases import aliases_eth, get_aliases, get_alias_address
from chains.account import Account
from tenacity import retry, stop_after_delay, wait_fixed


class MockEthereum:
    """
    An client implementation for a localnet/rinkebye/ropston Ethereum server
    """
    default_gas = 21000
    passphrase = 'the-passphrase'

    private_keys = [
        "ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2",
        "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032",
        "e810f1d7d6691b4a7a73476f3543bd87d601f9a53e7faf670eac2c5b517d83bf",
        "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
        "9294f4d108465fd293f7fe299e6923ef71a77f2cb1eb6d4394839c64ec25d5c0",
    ]

    def __init__(self, base_url):
        self.web3 = Web3(HTTPProvider(base_url))
        for key in self.private_keys:
            self.web3.geth.personal.import_raw_key(key, self.passphrase)
        self.accounts = self.web3.eth.accounts

    @classmethod
    def get_address_from_pubkey(cls, pubkey):
        """
        Get Ethereum address for a specific hrp (human readable part)
        bech32 encoded from a public key(secp256k1).

        :param string pubkey: public key
        :returns: string 0x encoded address
        """
        enc = bytearray.fromhex(pubkey)
        eth_pubkey = KeyAPI.PublicKey(enc)
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
        block = self.web3.eth.getBlock(self.web3.eth.defaultBlock)
        return block['number']

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
        return int(self.web3.eth.getBalance(address, 'latest') * Coin.ONE)

    @retry(stop=stop_after_delay(30), wait=wait_fixed(1))
    def wait_for_node(self):
        """
        Ethereum localnet node is started with directly mining 100 blocks
        to be able to start handling transactions.
        It can take a while depending on the machine specs so we retry.
        """
        current_height = self.get_block_height()
        if current_height < 20:
            logging.warning(
                f"Ethereum localnet starting, waiting"
            )
            raise Exception

    def transfer(self, txn):
        """
        Make a transaction/transfer on localnet Ethereum
        """
        self.wait_for_node()

        if not isinstance(txn.coins, list):
            txn.coins = [txn.coins]

        if txn.to_address in get_aliases():
            txn.to_address = get_alias_address(txn.chain, txn.to_address)

        if txn.from_address in get_aliases():
            txn.from_address = get_alias_address(txn.chain, txn.from_address)

        # update memo with actual address (over alias name)
        for alias in get_aliases():
            # we use RUNE BNB address to identify a cross chain stake
            if txn.memo.startswith("STAKE"):
                addr = get_alias_address("ETH", alias)
            else:
                addr = get_alias_address(txn.chain, alias)
            txn.memo = txn.memo.replace(alias, addr)

        amount = int(txn.coins[0].amount / Coin.ONE)

        # create and send transaction
        nonce = self.web3.eth.getTransactionCount(txn.from_address)
        tx = {'nonce': nonce, "from": txn.from_address, "to": txn.to_address, "value": amount,
                "data": txn.memo.encode().hex(), "gas": self.default_gas, "gasPrice": 1}

        self.web3.geth.personal.send_transaction(tx, self.passphrase)


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
        eth_amount = pool.get_rune_in_asset(int(rune_fee / 2))
        return Coin("ETH.ETH", eth_amount)

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
            txn.gas = [Coin("ETH.ETH", MockEthereum.default_gas)]

        from_acct.sub(txn.gas[0])
        from_acct.sub(txn.coins)
        to_acct.add(txn.coins)

        self.set_account(from_acct)
        self.set_account(to_acct)

        return txn.gas[0]
