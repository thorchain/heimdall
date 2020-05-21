import base64
import hashlib
import os
import json
import logging
import requests

import ecdsa

from utils.segwit_addr import address_from_public_key
from utils.common import HttpClient, Coin
from chains.aliases import get_alias_address, get_aliases

# Init logging
logging.basicConfig(
    format="%(asctime)s | %(levelname).4s | %(message)s",
    level=os.environ.get("LOGLEVEL", "INFO"),
)


# wallet helper functions
# Thanks to https://github.com/hukkinj1/cosmospy
def generate_wallet():
    privkey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1).to_string().hex()
    pubkey = privkey_to_pubkey(privkey)
    address = address_from_public_key(pubkey)
    return {"private_key": privkey, "public_key": pubkey, "address": address}


def privkey_to_pubkey(privkey):
    privkey_obj = ecdsa.SigningKey.from_string(
        bytes.fromhex(privkey), curve=ecdsa.SECP256k1
    )
    pubkey_obj = privkey_obj.get_verifying_key()
    return pubkey_obj.to_string("compressed").hex()


def privkey_to_address(privkey):
    pubkey = privkey_to_pubkey(privkey)
    return address_from_public_key(pubkey)


class ThorchainSigner(HttpClient):
    """
    A local simple implementation of thorchain chain
    """

    chain = "THOR"
    private_keys = {
        "USER-1": "ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2",
        "STAKER-1": "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032",
        "STAKER-2": "e810f1d7d6691b4a7a73476f3543bd87d601f9a53e7faf670eac2c5b517d83bf",
    }

    def transfer(self, txns):
        if not isinstance(txns, list):
            txns = [txns]

        for txn in txns:
            if not isinstance(txn.coins, list):
                txn.coins = [txn.coins]

            name = txn.from_address
            txn.gas = [Coin("THOR.RUNE", 100000000)]
            if txn.from_address in get_aliases():
                txn.from_address = get_alias_address(txn.chain, txn.from_address)
            if txn.to_address in get_aliases():
                txn.to_address = get_alias_address(txn.chain, txn.to_address)

            # update memo with actual address (over alias name)
            for alias in get_aliases():
                chain = txn.chain
                asset = txn.get_asset_from_memo()
                if asset:
                    chain = asset.get_chain()
                addr = get_alias_address(chain, alias)
                txn.memo = txn.memo.replace(alias, addr)

            acct = self._get_account(txn.from_address)

            payload = {
                "coins": [coin.to_thorchain_fmt() for coin in txn.coins],
                "memo": txn.memo,
                "base_req": {"chain_id": "thorchain", "from": txn.from_address},
            }

            payload = self.post("/thorchain/native/tx", payload)
            msgs = payload["value"]["msg"]
            fee = payload["value"]["fee"]
            acct_num = acct["result"]["value"]["account_number"]
            seq = acct["result"]["value"]["sequence"]
            sig = self._sign(
                name, self._get_sign_message("thorchain", acct_num, fee, seq, msgs)
            )
            pushable = self.get_pushable(name, msgs, sig, fee, acct_num, seq)
            result = self.send(pushable)
            txn.id = result["txhash"]

    def send(self, payload):
        resp = requests.post(self.get_url("/txs"), data=payload)
        resp.raise_for_status()
        return resp.json()

    def get_pushable(self, name, msgs, sig, fee, acct_num, seq) -> str:
        pubkey = privkey_to_pubkey(self.private_keys[name])
        base64_pubkey = base64.b64encode(bytes.fromhex(pubkey)).decode("utf-8")
        pushable_tx = {
            "tx": {
                "msg": msgs,
                "fee": fee,
                "memo": "",
                "signatures": [
                    {
                        "signature": sig,
                        "pub_key": {
                            "type": "tendermint/PubKeySecp256k1",
                            "value": base64_pubkey,
                        },
                        "account_number": str(acct_num),
                        "sequence": str(seq),
                    }
                ],
            },
            "mode": "sync",
        }
        return json.dumps(pushable_tx, separators=(",", ":"))

    def _sign(self, name, body):
        message_str = json.dumps(body, separators=(",", ":"), sort_keys=True)
        message_bytes = message_str.encode("utf-8")

        privkey = ecdsa.SigningKey.from_string(
            bytes.fromhex(self.private_keys[name]), curve=ecdsa.SECP256k1
        )
        signature_compact = privkey.sign_deterministic(
            message_bytes,
            hashfunc=hashlib.sha256,
            sigencode=ecdsa.util.sigencode_string_canonize,
        )

        signature_base64_str = base64.b64encode(signature_compact).decode("utf-8")
        return signature_base64_str

    def _get_sign_message(self, chain_id, acct_num, fee, seq, msgs):
        return {
            "chain_id": chain_id,
            "account_number": str(acct_num),
            "fee": fee,
            "memo": "",
            "sequence": str(seq),
            "msgs": msgs,
        }

    def _get_account(self, address):
        return self.fetch("/auth/accounts/" + address)
