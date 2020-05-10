import time
import logging
import json
import requests

from web3 import Web3, HTTPProvider
from eth_keys import KeyAPI
from utils.common import Coin
from chains.aliases import aliases_eth, get_aliases, get_alias_address
from chains.account import Account
from tenacity import retry, stop_after_delay, wait_fixed


def calculate_gas(msg):
    return MockEthereum.default_gas+MockEthereum.gas_per_byte*len(msg)


class MockEthereum:
    """
    An client implementation for a localnet/rinkebye/ropston Ethereum server
    """

    default_gas = 21000
    gas_per_byte = 68
    gwei = 1000000000
    passphrase = "the-passphrase"

    private_keys = [
        "ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2",
        "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032",
        "e810f1d7d6691b4a7a73476f3543bd87d601f9a53e7faf670eac2c5b517d83bf",
        "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
        "9294f4d108465fd293f7fe299e6923ef71a77f2cb1eb6d4394839c64ec25d5c0",
    ]

    def __init__(self, base_url, doimport):
        self.web3 = Web3(HTTPProvider(base_url))
        for key in self.private_keys:
            payload = json.dumps({"method": "personal_importRawKey", "params": [key, self.passphrase]})
            headers = {'content-type': "application/json", 'cache-control': "no-cache"}
            try:
                response = requests.request("POST", base_url, data=payload, headers=headers)
            except requests.exceptions.RequestException as e:
                logging.error(f"{e}")
            except:
                logging.info(f"Imported {key}")
            logging.info(f"accs {self.web3.eth.accounts}")

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
        return int(
            self.web3.eth.getBalance(Web3.toChecksumAddress(address), "latest")
            / self.gwei
            * Coin.ONE
        )

    @retry(stop=stop_after_delay(30), wait=wait_fixed(1))
    def wait_for_node(self):
        """
        Ethereum localnet node is started with directly mining 100 blocks
        to be able to start handling transactions.
        It can take a while depending on the machine specs so we retry.
        """
        current_height = self.get_block_height()
        while current_height < 3:
            current_height = self.get_block_height()

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
            chain = txn.chain
            asset = txn.get_asset_from_memo()
            if asset:
                chain = asset.get_chain()
            # we use RUNE BNB address to identify a cross chain stake
            if txn.memo.startswith("STAKE"):
                chain = "BNB"
            addr = get_alias_address(chain, alias)
            txn.memo = txn.memo.replace(alias, addr)

        logging.info(f"memo {txn.memo} len {len(txn.memo)}")
        amount = int(txn.coins[0].amount / Coin.ONE * self.gwei)

        logging.info(f"WOOOL")
        # create and send transaction
        gasPrice = self.web3.eth.gasPrice
        logging.info(f"gasPrice {gasPrice}")
        tx = {
            "from": Web3.toChecksumAddress(txn.from_address),
            "to": Web3.toChecksumAddress(txn.to_address),
            "value": amount,
            "data": "0x" + txn.memo.encode().hex(),
            "gas": calculate_gas(txn.memo),
        }
        from_bal = int(self.get_balance(Web3.toChecksumAddress(txn.from_address)))
        logging.info(f"bal {from_bal*10}")
        logging.info(f"amountt {amount}")
        self.web3.geth.personal.send_transaction(tx, self.passphrase)
        cur = self.get_block_height()
        while cur == self.get_block_height():
            time.sleep(1.0)

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
            txn.gas = [Coin("ETH.ETH", calculate_gas(txn.memo) * Coin.ONE)]

        from_acct.sub(txn.gas[0])
        from_acct.sub(txn.coins)
        to_acct.add(txn.coins)

        self.set_account(from_acct)
        self.set_account(to_acct)

        return txn.gas[0]
