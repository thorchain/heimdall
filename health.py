import argparse
import sys
import os
import logging

from chains import MockBinance
from thorchain import ThorchainClient
from midgard import MidgardClient
from common import Coin


# Init logging
logging.basicConfig(
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    level=os.environ.get("LOGLEVEL", "INFO"),
)


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
    except Exception as e:
        logging.error(e)
        sys.exit(1)


class Health:
    def __init__(self, thor, midgard, binance):
        self.errors = []
        self.thorchain_client = ThorchainClient(thor)
        self.thorchain_pools = []
        self.thorchain_asgard_vault = None
        self.thorchain_asgard_vault_address = None

        self.midgard_client = MidgardClient(midgard)
        self.midgard_pools = []

        self.mock_binance = MockBinance(binance)
        self.mock_binance_accounts = []

    def run(self):
        """Run health checks

        - check pools state between midgard and thorchain

        """
        self.retrieve_data()
        self.check_pools()
        self.check_asgard_vault()
        self.check_errors()

    def check_errors(self):
        """Check errors and exit accordingly.
        """
        for error in self.errors:
            logging.error(error)

        if len(self.errors):
            self.errors = []
            raise Exception("Health checks failed")

    def retrieve_data(self):
        """Retrieve data from APIs needed to run health checks.
        """
        self.thorchain_asgard_vault_address = self.thorchain_client.get_vault_address()
        self.thorchain_asgard_vault = self.thorchain_client.get_asgard_vault()

        self.mock_binance_accounts = self.mock_binance.accounts()

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
            trune_coin = Coin("RUNE-A1F", tpool["balance_rune"])
            tasset_coin = Coin(asset, tpool["balance_asset"])

            # Midgard Coins
            mrune_coin = Coin("RUNE-A1F", mpool["runeDepth"])
            masset_coin = Coin(asset, mpool["assetDepth"])

            # Check balances
            if trune_coin != mrune_coin:
                self.errors.append(
                    Exception(
                        f"Bad Midgard pool balance: BNB.RUNE-A1F"
                        f"{mrune_coin} != {trune_coin}"
                    )
                )

            if tasset_coin != masset_coin:
                self.errors.append(
                    Exception(
                        f"Bad Midgard pool balance: {asset} "
                        f"{masset_coin} != {tasset_coin}"
                    )
                )

            # Check pool units
            mpool_units = int(mpool["poolUnits"])
            tpool_units = int(tpool["pool_units"])
            if mpool_units != tpool_units:
                self.errors.append(
                    Exception(
                        f"Bad Midgard pool units: "
                        f"{mpool_units} != {tpool_units}"
                    )
                )

    def check_asgard_vault(self):
        for macct in self.mock_binance_accounts:
            if macct["address"] != self.thorchain_asgard_vault_address:
                continue
            for bal in macct["balances"]:
                macct_coin = Coin(bal["denom"], bal["amount"])
                for coin in self.thorchain_asgard_vault["coins"]:
                    asgard_coin = Coin.from_dict(coin)
                    if asgard_coin.asset != macct_coin.asset:
                        continue
                    if asgard_coin != macct_coin:
                        self.errors.append(
                            Exception(
                                f"Bad Asgard vault balance: {asgard_coin.asset} "
                                f"{asgard_coin} != {macct_coin} (Binance balance)"
                            )
                        )


if __name__ == "__main__":
    main()
