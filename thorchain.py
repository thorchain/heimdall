
from transaction import Transaction
from coin import Coin

class ThorchainState:
    def __init__(self):
        self.pools = []
        self.reserve = 0

    def get_pool(self, asset):
        """
        Fetch a specific pool by asset
        """
        for pool in self.pools:
            # TODO: remove this BNB specific check
            if pool.asset == asset or pool.asset == "BNB.{}".format(asset):
                return pool

        return Pool(asset)

    def set_pool(self, pool):
        """
        Set a pool
        """
        if not "." in pool.asset:
            pool.asset = "BNB.{}".format(pool.asset)

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
        elif txn.memo.startswith("SWAP:"):
            return self.handle_swap(txn)
        else:
            print("handler not recognized")
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

    def handle_swap(self, txn):
        """
        Does a swap (or double swap)
        """
        # parse memo
        parts = txn.memo.split(":")
        if len(parts) < 2:
            return self.refund(txn)

        address = None
        if len(parts) > 2:
            address = parts[2]
            # checking if address is for mainnet, not testnet
            if address.lower().startswith("bnb"):
                return self.refund(txn)

        limit = 0
        if len(parts) > 3:
            limit = int(parts[3] or "0")

        asset = parts[1]
        parts = asset.split(".")
        if len(parts) < 2:
            return self.refund(txn)

        chain = parts[0]
        symbol = parts[1]

        # check that we have one coin
        if len(txn.coins) != 1:
            return self.refund(txn)

        source = txn.coins[0].asset
        target = symbol

        # refund if we're trying to swap with the coin we given ie swapping bnb
        # with bnb
        if source == symbol:
            return self.refund(txn)

        pools = []
        if not txn.coins[0].is_rune() and not Coin(symbol, 0).is_rune():
            # its a double swap
            pool = self.get_pool(source)
            if pool.is_zero():
                return self.refund(txn)

            emit, pool = self.swap(txn.coins[0], "RUNE-A1F")
            pools.append(pool)
            txn.coins[0] = emit
            source = "RUNE-A1F"
            target = symbol

        asset = source
        if Coin(asset, 0).is_rune():
            asset = target

        pool = self.get_pool(asset)
        if pool.is_zero():
            return self.refund(txn)

        emit, pool = self.swap(txn.coins[0], symbol)
        pools.append(pool)
        if emit.is_zero() or (emit.amount < limit):
            return self.refund(txn)

        # save pools
        for pool in pools:
            self.set_pool(pool)
        return [Transaction(txn.chain, txn.toAddress, address or txn.fromAddress, [emit], "OUTBOUND:TODO")]

    def swap(self, coin, target):
        asset = target
        if not coin.is_rune():
            asset = coin.asset

        pool = self.get_pool(asset)
        if coin.is_rune():
            X = pool.rune_balance
            Y = pool.asset_balance
        else:
            X = pool.asset_balance
            Y = pool.rune_balance

        x = coin.amount
        emit = self.calc_asset_emission(X,x,Y)

        # if we emit zero, return immediately
        if emit == 0:
            return Coin(asset, emit), pool

        # copy pool
        newPool = Pool(pool.asset, pool.rune_balance, pool.asset_balance) 
        if coin.is_rune():
            newPool.add(x,0)
            newPool.sub(0,emit)
            emit = Coin(asset, emit)
        else:
            newPool.add(0,x)
            newPool.sub(emit,0)
            emit = Coin("RUNE-A1F", emit)

        return emit, newPool

    def calc_asset_emission(self, X, x, Y):
        # ( x * X * Y ) / ( x + X )^2
        return (x * X * Y) / (x + X)**2


class Pool:
    def __init__(self, asset, rune_amt=0, asset_amt=0):
        self.asset = asset
        self.rune_balance = rune_amt
        self.asset_balance = asset_amt

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

    def is_zero(self):
        return self.rune_balance == 0 and self.asset_balance == 0

    def __repr__(self):
        return "<Pool %s Rune: %d | Asset: %d>" % (self.asset, self.rune_balance, self.asset_balance)

    def __str__(self):
        return "Pool %s Rune: %d | Asset: %d" % (self.asset, self.rune_balance, self.asset_balance)
