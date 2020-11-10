from utils.common import HttpClient


class MidgardClient(HttpClient):
    """
    A client implementation to midgard API
    """

    def get_pool(self, assets):
        """Get pool data for specific set of assets.

        :param str asset: Assets name
        :returns: Pool data

        """
        if not isinstance(assets, list):
            assets = [assets]
        assets = ",".join(assets)
        return self.fetch(f"/v1/pools/detail?view=simple&asset={assets}")
