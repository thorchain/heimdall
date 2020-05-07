import hashlib

import bech32
import ecdsa

# wallet helper functions
# Thanks to https://github.com/hukkinj1/cosmospy
def generate_wallet():
    privkey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1).to_string().hex()
    pubkey = privkey_to_pubkey(privkey)
    address = pubkey_to_address(pubkey)
    return {"private_key": privkey, "public_key": pubkey, "address": address}


def privkey_to_pubkey(privkey):
    privkey_obj = ecdsa.SigningKey.from_string(bytes.fromhex(privkey), curve=ecdsa.SECP256k1)
    pubkey_obj = privkey_obj.get_verifying_key()
    return pubkey_obj.to_string("compressed").hex()


def pubkey_to_address(pubkey):
    pubkey_bytes = bytes.fromhex(pubkey)
    s = hashlib.new("sha256", pubkey_bytes).digest()
    r = hashlib.new("ripemd160", s).digest()
    five_bit_r = bech32.convertbits(r, 8, 5)
    assert five_bit_r is not None, "Unsuccessful bech32.convertbits call"
    return bech32.bech32_encode("thor", five_bit_r)


def privkey_to_address(privkey):
    pubkey = privkey_to_pubkey(privkey)
    return pubkey_to_address(pubkey)


print(privkey_to_address("ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2"))
print(privkey_to_address("289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"))
print(privkey_to_address("e810f1d7d6691b4a7a73476f3543bd87d601f9a53e7faf670eac2c5b517d83bf"))

class ThorchainClient:
    """
    A local simple implementation of thorchain chain
    """

    chain = "THOR"
    private_keys = {
        "USER-1": "ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2",
        "STAKER-1": "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032",
        "STAKER-2": "e810f1d7d6691b4a7a73476f3543bd87d601f9a53e7faf670eac2c5b517d83bf",
    }

    def __init__(self):
        pass

    def _sign(self, name):
        message_str = json.dumps(self._get_sign_message(), separators=(",", ":"), sort_keys=True)
        message_bytes = message_str.encode("utf-8")

        privkey = ecdsa.SigningKey.from_string(bytes.fromhex(self.private_keys[name]), curve=ecdsa.SECP256k1)
        signature_compact = privkey.sign_deterministic(
            message_bytes, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_string_canonize
        )

        signature_base64_str = base64.b64encode(signature_compact).decode("utf-8")
        return signature_base64_str

    def _get_sign_message(self):
        return {
            "chain_id": self._chain_id,
            "account_number": str(self._account_num),
            "fee": {
                "gas": str(self._gas),
                "amount": [{"amount": str(self._fee), "denom": self._fee_denom}],
            },
            "memo": self._memo,
            "sequence": str(self._sequence),
            "msgs": self._msgs,
        }
