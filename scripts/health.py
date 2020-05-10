import argparse
import sys
import os
import logging

from chains.binance import MockBinance, Account
from thorchain.thorchain import ThorchainClient
from thorchain.midgard import MidgardClient
from utils.common import Coin, get_rune_asset
from utils.segwit_addr import decode_address

# Init logging
logging.basicConfig(
    format="%(asctime)s | %(levelname).4s | %(message)s",
    level=os.environ.get("LOGLEVEL", "INFO"),
)

RUNE = get_rune_asset()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--thorchain", default="http://localhost:1317", help="Thorchain API url"
    )
    parser.add_argument(
        "--midgard", default="http://localhost:8080", help="Midgard API url"
    )
    parser.add_argument(
        "--binance", default="http://localhost:26660", help="Mock binance server"
    )

    args = parser.parse_args()

    health = Health(args.thorchain, args.midgard, args.binance)
    try:
        health.run()
        sys.exit(health.exit)
    except Exception as e:
        logging.error(e)
        sys.exit(1)


class Health:
    def __init__(self, thor, midgard, binance, fast_fail=False):
        self.thorchain_client = ThorchainClient(thor)
        self.thorchain_pools = []
        self.thorchain_asgard_vaults = []

        self.midgard_client = MidgardClient(midgard)
        self.midgard_pools = []

        self.binance_client = MockBinance(binance)
        self.binance_accounts = []
        self.fast_fail = fast_fail
        self.exit = 0

    def run(self):
        """Run health checks

        - check pools state between midgard and thorchain

        """
        self.retrieve_data()
        self.check_pools()
        self.check_asgard_vault()

    def error(self, err):
        """Check errors and exit accordingly.
        """
        self.exit = 1
        if self.fast_fail:
            raise Exception(err)
        else:
            logging.error(err)

    def retrieve_data(self):
        """Retrieve data from APIs needed to run health checks.
        """
        self.thorchain_asgard_vaults = self.thorchain_client.get_asgard_vaults()
        for vault in self.thorchain_asgard_vaults:
            if vault["coins"]:
                vault["coins"] = [Coin.from_dict(c) for c in vault["coins"]]

        self.binance_accounts = []
        accounts = self.binance_client.accounts()
        for acct in accounts:
            account = Account(acct["address"])
            if acct["balances"]:
                account.balances = [
                    Coin(b["denom"], b["amount"]) for b in acct["balances"]
                ]
                self.binance_accounts.append(account)

        self.thorchain_pools = self.thorchain_client.get_pools()
        if len(self.thorchain_pools) == 0:
            return
        pool_assets = [p["asset"] for p in self.thorchain_pools]
        self.midgard_pools = self.midgard_client.get_pool(pool_assets)

    def get_midgard_pool(self, asset):
        """Get midgard pool from class member.

        :param str asset: Asset name
        :returns: pool

        """
        for pool in self.midgard_pools:
            if pool["asset"] == asset:
                return pool

    def check_pools(self):
        """Check pools state between Midgard and Thorchain APIs.
        """
        for tpool in self.thorchain_pools:
            asset = tpool["asset"]
            mpool = self.get_midgard_pool(asset)

            # Thorchain Coins
            trune_coin = Coin(RUNE, tpool["balance_rune"])
            tasset_coin = Coin(asset, tpool["balance_asset"])

            # Midgard Coins
            mrune_coin = Coin(RUNE, mpool["runeDepth"])
            masset_coin = Coin(asset, mpool["assetDepth"])

            # Check balances
            if trune_coin != mrune_coin:
                self.error(
                    f"Bad Midgard Pool-{asset} balance: RUNE "
                    f"{mrune_coin} != {trune_coin}"
                )

            if tasset_coin != masset_coin:
                self.error(
                    f"Bad Midgard Pool-{asset} balance: ASSET "
                    f"{masset_coin} != {tasset_coin}"
                )

            # Check pool units
            mpool_units = int(mpool["poolUnits"])
            tpool_units = int(tpool["pool_units"])
            if mpool_units != tpool_units:
                self.error(
                    f"Bad Midgard Pool-{asset} units: "
                    f"{mpool_units} != {tpool_units}"
                )

    def check_binance_accounts(self, vault):
        # get raw pubkey from bech32 + amino encoded key
        # we need to get rid of the 5 first bytes used in amino encoding
        pub_key = decode_address(vault["pub_key"])[5:]
        vault_addr = MockBinance.get_address_from_pubkey(pub_key)
        for acct in self.binance_accounts:
            if acct.address != vault_addr:
                continue
            for bcoin in acct.balances:
                for vcoin in vault["coins"]:
                    if vcoin.asset != bcoin.asset:
                        continue
                    if vcoin != bcoin:
                        self.error(
                            Exception(
                                f"Bad Asgard vault balance: {vcoin.asset} "
                                f"{vcoin} != {bcoin} (Binance balance)"
                            )
                        )

    def check_asgard_vault(self):
        for vault in self.thorchain_asgard_vaults:
            # Check Binance balances
            self.check_binance_accounts(vault)


if __name__ == "__main__":
    main()
