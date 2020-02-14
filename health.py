import argparse
import sys

from thorchain import ThorchainClient
from midgard import MidgardClient
from exceptions import MidgardPoolError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--thorchain", default="http://localhost:1317", help="Thorchain API url"
    )
    parser.add_argument(
        "--midgard", default="http://localhost:8080", help="Midgard API url"
    )

    args = parser.parse_args()

    health = Health(args.thorchain, args.midgard)
    try:
        health.run()
    except Exception as e:
        print(e)
        sys.exit(1)


class Health:
    def __init__(self, thor, midgard):
        self.errors = []
        self.thorchain_client = ThorchainClient(thor)
        self.thorchain_pools = []
        self.thorchain_vaults = []

        self.midgard_client = MidgardClient(midgard)
        self.midgard_pools = []

    def run(self):
        """Run health checks

        - check pools state between midgard and thorchain

        """
        self.retrieve_data()
        self.check_pools()
        self.check_errors()

    def check_errors(self):
        """Check errors and exit accordingly.
        """
        for error in self.errors:
            print(error)

        if len(self.errors):
            raise Exception("Health checks failed")

    def retrieve_data(self):
        """Retrieve data from APIs needed to run health checks.
        """
        self.thorchain_pools = self.thorchain_client.get_pools()
        for pool in self.thorchain_pools:
            self.midgard_pools.append(self.midgard_client.get_pool(pool["asset"]))

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

            if int(tpool["balance_rune"]) != int(mpool["runeDepth"]):
                self.errors.append(
                    MidgardPoolError(
                        asset, "Balance RUNE", tpool["balance_rune"], mpool["runeDepth"]
                    )
                )

            if int(tpool["balance_asset"]) != int(mpool["assetDepth"]):
                self.errors.append(
                    MidgardPoolError(
                        asset,
                        "Balance {}".format(asset),
                        tpool["balance_asset"],
                        mpool["assetDepth"],
                    )
                )

            if int(tpool["pool_units"]) != int(mpool["poolUnits"]):
                self.errors.append(
                    MidgardPoolError(
                        asset, "Pool UNITS", tpool["pool_units"], mpool["poolUnits"]
                    )
                )


if __name__ == "__main__":
    main()
