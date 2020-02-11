
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
            "VAULT": {},
            "POOL-BNB": None,
            "POOL-LOK": None,
        }

        for name, acct in self.bnb.accounts.items():
            # ignore if is a new name
            if not name in snap:
                continue

            for coin in acct.balances:
                snap[name][coin.asset] = int(coin.amount)

        for pool in self.thorchain.pools:
            if pool.asset == "BNB.BNB":
                snap["POOL-BNB"] = {
                    "BNB": int(pool.asset_balance),
                    "RUNE-A1F": int(pool.rune_balance),
                }
            elif pool.asset == "BNB.LOK-3C0":
                snap["POOL-LOK"] = {
                    "LOK-3C0": int(pool.asset_balance),
                    "RUNE-A1F": int(pool.rune_balance),
                }

        return snap
