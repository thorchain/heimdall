
class Breakpoint:
    """
    This takes a snapshot picture of the chain(s) and generates json
    """

    def __init__(self, thorchain, bnb):
        self.bnb = bnb
        self.thorchain = thorchain

    def snapshot(self, txID, out):
        """
        Generate a snapshot picture of the bnb and thorchain balances to
        compare
        """
        snap = {
            "TX": txID,
            "OUT": out,
            "MASTER": {
                "BNB": 0,
                "LOK-3C0": 0,
                "RUNE-A1F": 0,
            },
            "USER-1": {
                "BNB": 0,
                "LOK-3C0": 0,
                "RUNE-A1F": 0,
            },
            "STAKER-1": {
                "BNB": 0,
                "LOK-3C0": 0,
                "RUNE-A1F": 0,
            },
            "STAKER-2": {
                "BNB": 0,
                "LOK-3C0": 0,
                "RUNE-A1F": 0,
            },
            "VAULT": {
                "BNB": 0,
                "LOK-3C0": 0,
                "RUNE-A1F": 0,
            },
            "POOL-BNB": {
                "BNB": 0,
                "RUNE-A1F": 0
            },
            "POOL-LOK": {
                "LOK-3C0": 0,
                "RUNE-A1F": 0
            },
        }

        for name, acct in self.bnb.accounts.items():
            for coin in acct.balances:
                snap[name][coin.asset] = coin.amount

        for pool in self.thorchain.pools:
            asset = pool.asset
            if asset == "BNB.BNB":
                snap["POOL-BNB"] = {
                    "BNB": pool.asset_balance,
                    "RUNE-A1F": pool.rune_balance,
                }
            elif asset == "BNB.LOK-3C0":
                snap["POOL-LOK"] = {
                    "LOK-3C0": pool.asset_balance,
                    "RUNE-A1F": pool.rune_balance,
                }

        return snap
