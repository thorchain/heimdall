import time
import logging
import base64
import hashlib
import codecs

from bitcoin import SelectParams
from bitcoin.rpc import Proxy
from bitcoin.wallet import CBitcoinSecret, P2WPKHBitcoinAddress
from bitcoin.core import x, CTransaction, Hash160
from bitcoin.core.script import CScript, OP_0
from common import Coin, Asset
from decimal import Decimal, getcontext
from segwit_addr import address_from_public_key
from chains.aliases import ALIASES_BTC, ALIASES_BNB


class MockBitcoin():
    """
    An client implementation for a regtest bitcoin server
    """

    private_keys = [
        "ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2",
        "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032",
        "e810f1d7d6691b4a7a73476f3543bd87d601f9a53e7faf670eac2c5b517d83bf",
        "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
        "9294f4d108465fd293f7fe299e6923ef71a77f2cb1eb6d4394839c64ec25d5c0",
    ]

    def __init__(self, base_url):
        SelectParams("regtest")
        self.connection = Proxy(service_url=base_url)
        for key in self.private_keys:
            seckey = CBitcoinSecret.from_secret_bytes(codecs.decode(key, 'hex_codec'))
            self.connection._call("importprivkey", str(seckey))

    @classmethod
    def get_address_from_pubkey(cls, pubkey):
        """
        Get bitcoin address for a specific hrp (human readable part)
        bech32 encoded from a public key(secp256k1).

        :param string pubkey: public key
        :returns: string bech32 encoded address
        """
        script_pubkey = CScript([OP_0, Hash160(pubkey)])
        return str(P2WPKHBitcoinAddress.from_scriptPubKey(script_pubkey))

    def set_vault_address(self, addr):
        """
        Set the vault bnb address
        """
        ALIASES_BTC["VAULT"] = addr

    def get_block_height(self):
        """
        Get the current block height of bitcoin regtest
        """
        return self.connection.getblockcount()

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

    def transfer(self, txn):
        """
        Make a transaction/transfer on regtest bitcoin
        """
        if not isinstance(txn.coins, list):
            txn.coins = [txn.coins]

        if txn.to_address in ALIASES_BTC:
            txn.to_address = ALIASES_BTC[txn.to_address]

        if txn.from_address in ALIASES_BTC:
            txn.from_address = ALIASES_BTC[txn.from_address]

        # update memo with actual address (over alias name)
        for name, addr in ALIASES_BNB.items():
            txn.memo = txn.memo.replace(name, addr)

        # create transaction
        amount = float(txn.coins[0].amount / Coin.ONE)
        tx_out_dest = {txn.to_address: amount}
        tx_out_op_return = {"data": txn.memo.encode().hex()}

        # get unspents UTXOs
        address = txn.from_address
        min_amount = amount + 0.01 # add more for fee
        unspents = self.connection._call(
            "listunspent", 1, 9999, [str(address)], True, {"minimumAmount": min_amount}
        )

        if len(unspents) == 0:
            raise Exception(
                f"Cannot transfer. No BTC UTXO available for {txn.from_address}"
            )

        # choose the first UTXO
        unspent = unspents[0]
        tx_in = [{ "txid": unspent["txid"], "vout": unspent["vout"] }]
        tx_out = [tx_out_dest]

        # create change output if needed
        amount_utxo = float(unspent["amount"])
        getcontext().prec = 15
        amount_change = Decimal(amount_utxo) - Decimal(min_amount)
        if amount_change > 0:
            tx_out.append({ txn.from_address: float(amount_change) })

        tx_out.append(tx_out_op_return)

        tx = self.connection._call("createrawtransaction", tx_in, tx_out)
        tx = self.connection._call("signrawtransactionwithwallet", tx)
        txn.id = self.connection._call("sendrawtransaction", tx["hex"])
