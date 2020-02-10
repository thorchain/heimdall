
from transaction import Transaction

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
        for i, p in enumerate(self.pools):
            if p.asset == pool.asset:
                self.pools[i] = pool
                return

        self.pools.append(pool)

    def handle_gas(self, gas):
        """
        Subtracts gas from pool
        """
        pool = self.get_pool(gas.asset)
        pool.sub(0, gas.amount)
        self.set_pool(pool)

    def refund(self, txn):
        """
        Returns a list of refund transactions based on given txn
        """
        txns = []
        for coin in txn.coins:
            txns.append(Transaction(txn.chain, txn.toAddress, txn.fromAddress, [coin], "REFUND"))
        return txns

    def handle(self, txn):
        """
        This is a router that sends a transaction to the correct handler. 
        It will return transactions to send
        """
        if txn.memo.startswith("STAKE:"):
            return self.handle_stake(txn)
        elif txn.memo.startswith("ADD:"):
            return self.handle_stake(txn)
        else:
            return self.refund(txn)

    def handle_add(self, txn):
        """
        Add assets to a pool
        """
        # parse memo
        parts = txn.memo.split(":")
        if len(parts) < 2:
            return self.refund(txn)

        asset = parts[1]
        parts = asset.split(".")
        if len(parts) < 2:
            return self.refund(txn)
        chain = parts[0]
        symbol = parts[1]

        # check that we have one rune and one asset
        if len(txn.coins) > 2:
            return self.refund(txn)
        for coin in txn.coins:
            if not coin.is_rune():
                if symbol != coin.asset:
                    return self.refund(txn) # mismatch coin asset and memo

        pool = self.get_pool(asset)
        for coin in txn.coins:
            if coin.is_rune():
                pool.add(coin.amount, 0)
            else:
                pool.add(0, coin.amount)

        self.set_pool(pool)

        return []




    def handle_stake(self, txn):
        """
        handles a staking transaction
        """
        # parse memo
        parts = txn.memo.split(":")
        if len(parts) < 2:
            return self.refund(txn)

        asset = parts[1]
        parts = asset.split(".")
        if len(parts) < 2:
            return self.refund(txn)
        chain = parts[0]
        symbol = parts[1]

        # check that we have one rune and one asset
        if len(txn.coins) > 2:
            return self.refund(txn)
        for coin in txn.coins:
            if not coin.is_rune():
                if symbol != coin.asset:
                    return self.refund(txn) # mismatch coin asset and memo

        pool = self.get_pool(asset)
        for coin in txn.coins:
            if coin.is_rune():
                pool.add(coin.amount, 0)
            else:
                pool.add(0, coin.amount)

        self.set_pool(pool)

        return []


class Pool:
    def __init__(self, asset):
        self.asset = asset
        self.rune_balance = 0
        self.asset_balance = 0

    def sub(self, rune_amt, asset_amt):
        """
        Subtracts from pool
        """
        self.rune_balance -= rune_amt
        self.asset_balance -= asset_amt
        if self.asset_balance < 0 or self.rune_balance < 0:
            print("Overdrawn pool", self)
            raise Exception("insufficient funds")

    def add(self, rune_amt, asset_amt):
        """
        Add to pool
        """
        self.rune_balance += rune_amt
        self.asset_balance += asset_amt

    def __repr__(self):
        return "<Pool %s Rune: %d | Asset: %d>" % (self.asset, self.rune_balance, self.asset_balance)

    def __str__(self):
        return "Pool %s Rune: %d | Asset: %d" % (self.asset, self.rune_balance, self.asset_balance)
