
class ThorchainState:
    def __init__(self):
        self.pools = []
        self.reserve = 0

    def get_pool(self, asset):
        """
        Fetch a specific pool by asset
        """
        for pool in self.pools:
            if pool.asset == asset:
                return pool

        return Pool(asset)

    def set_pool(self, pool):
        """
        Set a pool
        """
        for p in self.pools:
            if p.asset == pool.asset:
                p = pool
                return

        self.pools.append(pool)

    def handle(self, txn):
        """
        This is a router that sends a transaction to the correct handler. This
        returns a boolean that determines if it should trigger a refund
        """
        if txn.memo.startswith("STAKE:"):
            return self.handle_stake(txn)
        else:
            return False

    def handle_stake(self, txn):
        """
        handles a staking transaction
        """
        parts = txn.memo.split(":")
        asset = parts[1]
        parts = asset.split(".")
        chain = parts[0]
        symbol = parts[1]

        pool = self.get_pool(asset)
        for coin in txn.coins:
            if coin.is_rune():
                pool.rune_balance += coin.amount
            else:
                pool.asset_balance += coin.amount

        self.set_pool(pool)

        return True, 0


class Pool:
    def __init__(self, asset):
        self.asset = asset
        self.rune_balance = 0
        self.asset_balance = 0

    def __repr__(self):
        return "<Pool %s Rune: %d | Asset: %d>" % (self.asset, self.rune_balance, self.asset_balance)

    def __str__(self):
        return "Pool %s Rune: %d | Asset: %d" % (self.asset, self.rune_balance, self.asset_balance)
