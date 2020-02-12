from copy import deepcopy

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
        if pool.asset_balance <= gas.amount:
            pool.asset_balance = 0
        else:
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
            return self.handle_add(txn)
        elif txn.memo.startswith("WITHDRAW:"):
            return self.handle_unstake(txn)
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
        rune_amt = 0
        asset_amt = 0
        for coin in txn.coins:
            if coin.is_rune():
                rune_amt = coin.amount
            else:
                asset_amt = coin.amount

        pool.stake(txn.fromAddress, rune_amt, asset_amt)

        self.set_pool(pool)

        return []

    def handle_unstake(self, txn):
        """
        handles a unstaking transaction
        """
        withdraw_basis_points = 10000

        # parse memo
        parts = txn.memo.split(":")
        if len(parts) < 2:
            return self.refund(txn)

        if len(parts) >= 3:
            withdraw_basis_points = int(parts[2])

        asset = parts[1]
        parts = asset.split(".")
        if len(parts) < 2:
            return self.refund(txn)
        chain = parts[0]
        symbol = parts[1]

        pool = self.get_pool(symbol)
        staker = pool.get_staker(txn.fromAddress)
        if staker.is_zero():
            return self.refund(txn)

        rune_amt, asset_amt = pool.unstake(txn.fromAddress, withdraw_basis_points)
        self.set_pool(pool)

        chain, _from, _to = txn.chain, txn.fromAddress, txn.toAddress
        return [
            Transaction(chain, _to, _from, [Coin("RUNE-A1F", rune_amt)], "OUTBOUND"),
            Transaction(chain, _to, _from, [Coin(symbol, asset_amt)], "OUTBOUND"),
        ]

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
        return [Transaction(txn.chain, txn.toAddress, address or txn.fromAddress, [emit], "OUTBOUND")]

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

        newPool = deepcopy(pool) # copy of pool
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
        return int((x * X * Y) / (x + X)**2)


class Pool:
    def __init__(self, asset, rune_amt=0, asset_amt=0):
        self.asset = asset
        self.rune_balance = rune_amt
        self.asset_balance = asset_amt
        self.total_units = 0
        self.stakers = []

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
        """
        Check if pool has zero balance
        """
        return self.rune_balance == 0 and self.asset_balance == 0

    def get_staker(self, address):
        """
        Fetch a specific staker by address
        """
        for staker in self.stakers:
            if staker.address == address:
                return staker

        return Staker(address)

    def set_staker(self, staker):
        """
        Set a staker
        """
        for i, s in enumerate(self.stakers):
            if s.address == staker.address:
                self.stakers[i] = staker
                return

        self.stakers.append(staker)

    def stake(self, address, rune_amt, asset_amt):
        """
        Stake rune/asset for an address
        """
        staker = self.get_staker(address)
        self.add(rune_amt, asset_amt)
        units = self._calc_stake_units(
            self.rune_balance, 
            self.asset_balance, 
            rune_amt, 
            asset_amt,
        )

        self.total_units += units
        staker.units += units
        self.set_staker(staker)

    def unstake(self, address, withdraw_basis_points):
        """
        Unstake from an address with given withdraw basis points
        """
        if withdraw_basis_points > 10000 or withdraw_basis_points < 0:
            raise Exception("withdraw basis points should be between 0 - 10,000")

        staker = self.get_staker(address)
        units, rune_amt, asset_amt = self._calc_unstake_units(staker.units, withdraw_basis_points)
        staker.units -= units
        self.set_staker(staker)
        self.total_units -= units
        self.sub(rune_amt, asset_amt)
        print("POOL", self, rune_amt, asset_amt)
        return rune_amt, asset_amt

    def _calc_stake_units(self, pool_rune, pool_asset, stake_rune, stake_asset):
        """
        Calculate staker units
        ((R + A) * (r * A + R * a))/(4 * R * A)
        R = pool rune balance after
        A = pool asset balance after
        r = staked rune
        a = staked asset
        """
        return int(round((float(((pool_rune + pool_asset) * (stake_rune * pool_asset + pool_rune * stake_asset)))/float((4 * pool_rune * pool_asset)))))

    def _calc_unstake_units(self, staker_units, withdraw_basis_points):
        """
        Calculate amount of rune/asset to unstake
        Returns staker units, rune amount, asset amount
        """
        units_to_claim = int(round(self._share(withdraw_basis_points, 10000, staker_units)))
        withdraw_rune = int(round(self._share(units_to_claim, self.total_units, self.rune_balance)))
        withdraw_asset = int(round(self._share(units_to_claim, self.total_units, self.asset_balance)))
        units_after = staker_units - units_to_claim
        if units_after < 0:
            print("Overdrawn staker units", self)
            raise Exception("Overdrawn staker units")
        return units_to_claim, withdraw_rune, withdraw_asset

    def _share(self, part, total, alloc):
        """
        Calculates the share of something
        (Allocation / (Total / part))
        """
        return float(alloc) / (float(total) / float(part))

    def __repr__(self):
        return "<Pool %s Rune: %d | Asset: %d>" % (self.asset, self.rune_balance, self.asset_balance)

    def __str__(self):
        return "Pool %s Rune: %d | Asset: %d" % (self.asset, self.rune_balance, self.asset_balance)


class Staker:
    def __init__(self, address, units = 0):
        self.address = address
        self.units = 0
    
    def add(self, units):
        """
        Add staker units
        """
        self.units += units

    def sub(self, units):
        """
        Subtract staker units
        """
        self.units -= units
        if self.units < 0:
            print("Overdrawn staker", self)
            raise Exception("insufficient staker units")

    def is_zero(self):
        return self.units <= 0

    def __repr__(self):
        return "<Staker %s Units: %d>" % (self.address, self.units)

    def __str__(self):
        return "Staker %s Units: %d" % (self.address, self.units)
