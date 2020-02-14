from common import HttpClient


class MidgardClient(HttpClient):
    """
    A client implementation to midgard API
    """

    def get_pool(self, asset):
        """Get pool data for a specific asset.

        :param str asset: Asset name
        :returns: Pool data

        """
        return self.fetch("/v1/pools/{}".format(asset))
