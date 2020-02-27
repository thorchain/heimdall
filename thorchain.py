import time
import json
import logging
import itertools
from copy import deepcopy

from common import (
    Transaction,
    Coin,
    Asset,
    get_share,
    HttpClient,
)


class ThorchainClient(HttpClient):
    """
    A client implementation to thorchain API
    """

    def get_block_height(self):
        """
        Get the current block height of mock binance
        """
        data = self.fetch("/thorchain/lastblock")
        return int(data["statechain"])

    def wait_for_blocks(self, count):
        """
        Wait for the given number of blocks
        """
        start_block = self.get_block_height()
        for x in range(0, 100):
            time.sleep(1)
            block = self.get_block_height()
            if block - start_block >= count:
                return
        raise Exception(f"failed waiting for thorchain blocks ({count})")

    def get_vault_address(self):
        data = self.fetch("/thorchain/pool_addresses")
        return data["current"][0]["address"]

    def get_vault_data(self):
        return self.fetch("/thorchain/vault")

    def get_pools(self):
        return self.fetch("/thorchain/pools")

    def get_events(self, id=1):
        return self.fetch(f"/thorchain/events/{id}")


class ThorchainState:
    """
    A complete implementation of the thorchain logic/behavior
    """

    def __init__(self):
        self.pools = []
        self.events = []
        self.reserve = 0
        self.liquidity = {}
        self.total_bonded = 0
        self.bond_reward = 0

    def get_pool(self, asset):
        """
        Fetch a specific pool by asset
        """
        for pool in self.pools:
            if pool.asset.is_equal(asset):
                return pool

        return Pool(asset)

    def set_pool(self, pool):
        """
        Set a pool
        """
        for i, p in enumerate(self.pools):
            if p.asset.is_equal(pool.asset):
                self.pools[i] = pool
                return

        self.pools.append(pool)

    def get_events(self, id=1):
        """
        Get events starting from id

        :param int id: id number to start getting events
        :returns: list of events

        """
        events = []
        for event in self.events:
            if event.id >= id:
                events.append(event)
        return events

    def handle_gas(self, gas):
        """
        Subtracts gas from pool
        """
        pool = self.get_pool(gas.asset)
        # TODO: this is a hacky way to avoid the problem of gas overdrawing a
        # balance. clean this up later
        if pool.asset_balance <= gas.amount:
            pool.asset_balance = 0
        else:
            pool.sub(0, gas.amount)  # subtract gas from pool

            # figure out how much rune is an equal amount to gas.amount
            rune_amt = pool.get_asset_in_rune(gas.amount)
            self.reserve -= rune_amt  # take rune from the reserve
            pool.add(rune_amt, 0)  # replenish gas costs with rune

        self.set_pool(pool)

    def handle_fee(self, txns):
        """
        Subtract transaction fee from given transactions
        """
        rune_fee = 100000000
        outbound = []
        if not isinstance(txns, list):
            txns = [txns]

        for txn in txns:
            for coin in txn.coins:
                if coin.is_rune():
                    coin.amount -= rune_fee  # deduct 1 rune transaction fee
                    self.reserve += rune_fee  # add to the reserve
                    if coin.amount > 0:
                        outbound.append(txn)
                else:
                    pool = self.get_pool(coin.asset)

                    if not pool.is_zero():
                        asset_fee = (
                            pool.get_asset_fee()
                        )  # default to zero if pool is empty
                        pool.add(0, asset_fee)
                        pool.sub(rune_fee, 0)
                        self.set_pool(pool)
                        coin.amount -= asset_fee

                    self.reserve += rune_fee  # add to the reserve
                    if coin.amount > 0:
                        outbound.append(txn)

        return outbound

    def _total_liquidity(self):
        """
        Total up the liquidity fees from all pools
        """
        total = 0
        for value in self.liquidity.values():
            total += value
        return total

    def handle_rewards(self):
        """
        Calculate block rewards
        """
        if self.reserve == 0:
            return

        if self._total_liquidity() == 0:
            return

        # calculate the block rewards based on the reserve, emission curve, and
        # blocks in a year
        emission_curve = 6
        blocks_per_year = 6311390
        block_rewards = int(
            round(float(self.reserve) / emission_curve / blocks_per_year)
        )

        # total income made on the network
        system_income = block_rewards + self._total_liquidity()

        # get the total staked
        # TODO: skip non-enabled pools
        total_staked = 0
        for pool in self.pools:
            total_staked += pool.rune_balance

        if total_staked == 0:  # nothing staked, no rewards
            return

        # Targets a linear change in rewards from 0% staked, 33% staked, 100% staked.
        # 0% staked: All rewards to stakers, 0 to bonders
        # 33% staked: 33% to stakers
        # 100% staked: All rewards to Bonders, 0 to stakers

        staker_split = 0
        # Zero payments to stakers when staked == bonded
        if total_staked < self.total_bonded:
            # (y + x) / (y - x)
            factor = float(self.total_bonded + total_staked) / float(
                self.total_bonded - total_staked
            )
            staker_split = int(round(system_income / factor))

        bond_reward = system_income - staker_split

        # calculate if we need to move liquidity from the pools to the bonders,
        # or move bond rewards to the pools
        pool_reward = 0
        staker_deficit = 0
        if staker_split >= self._total_liquidity():
            pool_reward = staker_split - self._total_liquidity()
        else:
            staker_deficit = self._total_liquidity() - staker_split

        if self.reserve < bond_reward + pool_reward:
            return

        # subtract our rewards from the reserve
        self.reserve -= bond_reward + pool_reward
        self.bond_reward += bond_reward  # add to bond reward pool

        if pool_reward > 0:
            # TODO: subtract any remaining gas, from the pool rewards
            if self._total_liquidity() > 0:
                for key, value in self.liquidity.items():
                    share = int(
                        round(get_share(value, self._total_liquidity(), pool_reward))
                    )
                    pool = self.get_pool(key)
                    pool.rune_balance += share
                    self.set_pool(pool)
            else:
                pass  # TODO: Pool Rewards are based on Depth Share
        else:
            for key, value in self.liquidity.items():
                share = int(
                    round(get_share(staker_deficit, self._total_liquidity(), value))
                )
                pool = self.get_pool(key)
                pool.rune_balance -= share
                self.bond_reward += share
                self.set_pool(pool)

        # clear summed liquidity fees
        self.liquidity = {}

    def refund(self, txn, refund_event=None):
        """
        Returns a list of refund transactions based on given txn
        """
        txns = []
        for coin in txn.coins:
            txns.append(
                Transaction(
                    txn.chain, txn.to_address, txn.from_address, [coin], "REFUND:TODO"
                )
            )

        # generate event REFUND for the transaction
        event = Event("refund", txn, txns, refund_event)
        self.events.append(event)
        return txns

    def handle(self, txn):
        """
        This is a router that sends a transaction to the correct handler.
        It will return transactions to send

        :param txn: txn IN
        :returns: txs OUT

        """
        tx = deepcopy(txn)  # copy of transaction
        if tx.memo.startswith("STAKE:"):
            return self.handle_stake(tx)
        elif tx.memo.startswith("ADD:"):
            return self.handle_add(tx)
        elif tx.memo.startswith("WITHDRAW:"):
            return self.handle_unstake(tx)
        elif tx.memo.startswith("SWAP:"):
            return self.handle_swap(tx)
        elif tx.memo.startswith("RESERVE"):
            return self.handle_reserve(tx)
        else:
            logging.warning("handler not recognized")
            if tx.memo == "":
                refund_event = RefundEvent(105, "memo can't be empty")
            else:
                refund_event = RefundEvent(105, f"invalid tx type: {tx.memo}")
            return self.refund(tx, refund_event)

    def handle_reserve(self, txn):
        """
        Add rune to the reserve
        MEMO: RESERVE
        """
        amount = 0
        for coin in txn.coins:
            if coin.is_rune():
                self.reserve += coin.amount
                amount += coin.amount

        # generate event for RESERVE transaction
        reserve_event = ReserveEvent(txn.from_address, amount)
        event = Event("reserve", txn, None, reserve_event)
        self.events.append(event)

        return []

    def handle_add(self, txn):
        """
        Add assets to a pool
        MEMO: ADD:<asset(req)>
        """
        # parse memo
        parts = txn.memo.split(":")
        if len(parts) < 2:
            if txn.memo == "":
                refund_event = RefundEvent(105, "memo can't be empty")
            else:
                refund_event = RefundEvent(105, f"invalid tx type: {txn.memo}")
            return self.refund(txn, refund_event)

        asset = Asset(parts[1])

        # check that we have one rune and one asset
        if len(txn.coins) > 2:
            # FIXME real world message
            refund_event = RefundEvent(105, "refund reason message")
            return self.refund(txn, refund_event)

        for coin in txn.coins:
            if not coin.is_rune():
                if not asset.is_equal(coin.asset):
                    # mismatch coin asset and memo
                    refund_event = RefundEvent(105, "Invalid symbol")
                    return self.refund(txn, refund_event)

        pool = self.get_pool(asset)
        for coin in txn.coins:
            if coin.is_rune():
                pool.add(coin.amount, 0)
            else:
                pool.add(0, coin.amount)

        self.set_pool(pool)

        # generate event for ADD transaction
        add_event = AddEvent(pool.asset)
        event = Event("add", txn, None, add_event)
        self.events.append(event)

        return []

    def handle_stake(self, txn):
        """
        handles a staking transaction
        MEMO: STAKE:<asset(req)>
        """
        # parse memo
        parts = txn.memo.split(":")
        if len(parts) < 2:
            if txn.memo == "":
                refund_event = RefundEvent(105, "memo can't be empty")
            else:
                refund_event = RefundEvent(105, f"invalid tx type: {txn.memo}")
            return self.refund(txn, refund_event)

        # empty asset
        if parts[1] == "":
            refund_event = RefundEvent(105, "Invalid symbol")
            return self.refund(txn, refund_event)

        asset = Asset(parts[1])

        # cant have rune memo
        if asset.is_rune():
            refund_event = RefundEvent(105, "invalid stake memo:invalid pool asset")
            return self.refund(txn, refund_event)

        # check that we have one rune and one asset
        if len(txn.coins) > 2:
            # FIXME real world message
            refund_event = RefundEvent(105, "refund reason message")
            return self.refund(txn, refund_event)

        # check for mismatch coin asset and memo
        for coin in txn.coins:
            if not coin.is_rune():
                if not asset.is_equal(coin.asset):
                    refund_event = RefundEvent(
                        105, f"invalid stake memo: did not find {asset}"
                    )
                    return self.refund(txn, refund_event)

        pool = self.get_pool(asset)
        rune_amt = 0
        asset_amt = 0
        for coin in txn.coins:
            if coin.is_rune():
                rune_amt = coin.amount
            else:
                asset_amt = coin.amount

        pool.stake(txn.from_address, rune_amt, asset_amt)

        self.set_pool(pool)

        # generate event for STAKE transaction
        stake_event = StakeEvent(pool.asset, pool.total_units)
        event = Event("stake", txn, None, stake_event)
        self.events.append(event)

        return []

    def handle_unstake(self, txn):
        """
        handles a unstaking transaction
        MEMO: WITHDRAW:<asset(req)>:<address(op)>:<basis_points(op)>
        """
        withdraw_basis_points = 10000

        # parse memo
        parts = txn.memo.split(":")
        if len(parts) < 2:
            if txn.memo == "":
                refund_event = RefundEvent(105, "memo can't be empty")
            else:
                refund_event = RefundEvent(105, f"invalid tx type: {txn.memo}")
            return self.refund(txn, refund_event)

        # get withdrawal basis points, if it exists in the memo
        if len(parts) >= 3:
            withdraw_basis_points = int(parts[2])

        # empty asset
        if parts[1] == "":
            refund_event = RefundEvent(105, "Invalid symbol")
            return self.refund(txn, refund_event)

        asset = Asset(parts[1])

        pool = self.get_pool(asset)
        staker = pool.get_staker(txn.from_address)
        if staker.is_zero():
            # FIXME real world message
            refund_event = RefundEvent(105, "refund reason message")
            return self.refund(txn, refund_event)

        rune_amt, asset_amt = pool.unstake(txn.from_address, withdraw_basis_points)
        self.set_pool(pool)

        # out transactions
        chain, _from, _to = txn.chain, txn.from_address, txn.to_address
        out_txns = [
            Transaction(
                chain, _to, _from, [Coin("RUNE-A1F", rune_amt)], "OUTBOUND:TODO"
            ),
            Transaction(chain, _to, _from, [Coin(asset, asset_amt)], "OUTBOUND:TODO"),
        ]

        # generate event for UNSTAKE transaction
        unstake_event = UnstakeEvent(
            pool.asset, pool.total_units, withdraw_basis_points, 0
        )
        event = Event("unstake", txn, out_txns, unstake_event)
        self.events.append(event)

        return out_txns

    def handle_swap(self, txn):
        """
        Does a swap (or double swap)
        MEMO: SWAP:<asset(req)>:<address(op)>:<target_trade(op)>
        """
        # parse memo
        parts = txn.memo.split(":")
        if len(parts) < 2:
            if txn.memo == "":
                refund_event = RefundEvent(105, "memo can't be empty")
            else:
                refund_event = RefundEvent(105, f"invalid tx type: {txn.memo}")
            return self.refund(txn, refund_event)

        # get address to send to
        address = txn.from_address
        if len(parts) > 2:
            address = parts[2]
            # checking if address is for mainnet, not testnet
            if address.lower().startswith("bnb"):
                # FIXME real world message
                refund_event = RefundEvent(105, "checksum failed. Expected ...")
                return self.refund(txn, refund_event)

        # get trade target, if exists
        target_trade = 0
        if len(parts) > 3:
            target_trade = int(parts[3] or "0")

        asset = Asset(parts[1])

        # check that we have one coin
        if len(txn.coins) != 1:
            refund_event = RefundEvent(
                105, "invalid swap memo:not expecting multiple coins in a swap"
            )
            return self.refund(txn, refund_event)

        source = txn.coins[0].asset
        target = asset

        # refund if we're trying to swap with the coin we given ie swapping bnb
        # with bnb
        if source.is_equal(asset):
            refund_event = RefundEvent(
                105, f"invalid swap memo:swap from {source} to {target} is noop, refund"
            )
            return self.refund(txn, refund_event)

        pools = []

        if not txn.coins[0].is_rune() and not asset.is_rune():
            # its a double swap
            pool = self.get_pool(source)
            if pool.is_zero():
                # FIXME real world message
                refund_event = RefundEvent(105, "refund reason message")
                return self.refund(txn, refund_event)

            emit, liquidity_fee, trade_slip, pool = self.swap(txn.coins[0], "RUNE-A1F")
            if str(pool.asset) not in self.liquidity:
                self.liquidity[str(pool.asset)] = 0
            self.liquidity[str(pool.asset)] += liquidity_fee

            # generate event for SWAP transaction
            out_txns = [
                Transaction(txn.chain, address, txn.to_address, [emit], txn.memo)
            ]
            swap_event = SwapEvent(pool.asset, 0, trade_slip, liquidity_fee)
            event = Event("swap", deepcopy(txn), out_txns, swap_event)
            self.events.append(event)

            pools.append(pool)
            txn.coins[0] = emit
            source = Asset("RUNE-A1F")
            target = asset

        # set asset to non-rune asset
        asset = source
        if asset.is_rune():
            asset = target

        pool = self.get_pool(asset)
        if pool.is_zero():
            # FIXME real world message
            refund_event = RefundEvent(105, "refund reason message: pool is zero")
            return self.refund(txn, refund_event)

        emit, liquidity_fee, trade_slip, pool = self.swap(txn.coins[0], asset)
        pools.append(pool)

        # check emit is non-zero and is not less than the target trade
        if emit.is_zero() or (emit.amount < target_trade):
            refund_event = RefundEvent(
                105, f"emit asset {emit.amount} less than price limit {target_trade}"
            )
            return self.refund(txn, refund_event)

        if str(pool.asset) not in self.liquidity:
            self.liquidity[str(pool.asset)] = 0
        self.liquidity[str(pool.asset)] += liquidity_fee

        # save pools
        for pool in pools:
            self.set_pool(pool)

        out_txns = [
            Transaction(txn.chain, txn.to_address, address, [emit], "OUTBOUND:TODO")
        ]

        # generate event for SWAP transaction
        swap_event = SwapEvent(pool.asset, target_trade, trade_slip, liquidity_fee)
        event = Event("swap", txn, out_txns, swap_event)
        self.events.append(event)

        return out_txns

    def swap(self, coin, target):
        """
        Does a swap returning amount of coins emitted and new pool

        :param Coin coin: coin sent to swap
        :param Asset target: target asset
        :returns: list of events
            - emit (int) - number of coins to be emitted for the swap
            - liquidity_fee (int) - liquidity fee
            - trade_slip (int) - trade slip
            - pool (Pool) - pool with new values

        """
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
        emit = self._calc_asset_emission(X, x, Y)

        # calculate the liquidity fee (in rune)
        liquidity_fee = self._calc_liquidity_fee(X, x, Y)
        if coin.is_rune():
            liquidity_fee = pool.get_asset_in_rune(liquidity_fee)

        # calculate trade slip
        trade_slip = self._calc_trade_slip(X, x)

        # if we emit zero, return immediately
        if emit == 0:
            return Coin(asset, emit), 0, 0, pool

        newPool = deepcopy(pool)  # copy of pool
        if coin.is_rune():
            newPool.add(x, 0)
            newPool.sub(0, emit)
            emit = Coin(asset, emit)
        else:
            newPool.add(0, x)
            newPool.sub(emit, 0)
            emit = Coin("RUNE-A1F", emit)

        return emit, liquidity_fee, trade_slip, newPool

    def _calc_liquidity_fee(self, X, x, Y):
        """
        Calculate the liquidity fee from a trade
        ( x^2 *  Y ) / ( x + X )^2

        :param int X: first balance
        :param int x: asset amount
        :param int Y: second balance
        :returns: (int) liquidity fee

        """
        return int(float((x ** 2) * Y) / float((x + X) ** 2))

    def _calc_trade_slip(self, X, x):
        """
        Calculate the trade slip from a trade
        expressed in basis points (10,000)
        x * (2*X + x) / (X * X)

        :param int X: first balance
        :param int x: asset amount
        :returns: (int) trade slip

        """
        return int(10000 * (x * (2 * X + x) / (X ** 2)))

    def _calc_asset_emission(self, X, x, Y):
        """
        Calculates the amount of coins to be emitted in a swap
        ( x * X * Y ) / ( x + X )^2

        :param int X: first balance
        :param int x: asset amount
        :param int Y: second balance
        :returns: (int) asset emission

        """
        return int((x * X * Y) / (x + X) ** 2)


class Event:
    """
    Event class representing events generated by thorchain
    after handling transactions.
    """

    id_iter = itertools.count(1)

    def __init__(self, event_type, txn, txns_out, event, gas=None, status="Success"):
        self.id = next(Event.id_iter)
        self.type = event_type
        self.in_tx = txn
        self.out_txs = txns_out
        self.gas = gas
        self.event = event
        self.status = status

    def __repr__(self):
        return "<Event [%s-%s] %s ==> %s | %s>" % (
            self.id,
            self.type,
            self.in_tx,
            self.out_txs,
            self.event,
        )

    def __str__(self):
        return "Event [%s-%s] %s ==> %s | %s" % (
            self.id,
            self.type,
            self.in_tx,
            self.out_txs,
            self.event,
        )

    def to_json(self):
        return json.dumps(self, default=lambda x: x.__dict__)


class RefundEvent:
    """
    Event refund class specific to REFUND events.
    """

    def __init__(self, code, reason):
        self.code = code
        self.reason = reason


class ReserveEvent:
    """
    Event reserve class specific to RESERVE events.
    """

    def __init__(self, address, amount):
        self.reserve_contributor = {
            "address": address,
            "amount": amount,
        }


class SwapEvent:
    """
    Event swap class specific to SWAP events.
    """

    def __init__(self, pool, price_target, trade_slip, liquidity_fee):
        self.pool = pool
        self.price_target = price_target
        self.trade_slip = trade_slip
        self.liquidity_fee = liquidity_fee


class StakeEvent:
    """
    Event stake class specific to STAKE events.
    """

    def __init__(self, asset, pool_units):
        self.pool = asset
        self.stake_units = pool_units


class UnstakeEvent:
    """
    Event unstake class specific to UNSTAKE events.
    """

    def __init__(self, asset, pool_units, basis_points, asymmetry):
        self.pool = asset
        self.stake_units = pool_units
        self.basis_points = basis_points
        self.asymmetry = asymmetry


class AddEvent:
    """
    Event add class specific to ADD events.
    """

    def __init__(self, asset):
        self.pool = asset


class Pool:
    def __init__(self, asset, rune_amt=0, asset_amt=0):
        self.asset = asset
        if isinstance(asset, str):
            self.asset = Asset(asset)
        self.rune_balance = rune_amt
        self.asset_balance = asset_amt
        self.total_units = 0
        self.stakers = []

    def get_asset_in_rune(self, val):
        """
        Get an equal amount of given value in rune
        """
        if self.is_zero():
            return 0

        share = get_share(self.rune_balance, self.asset_balance, val)
        return int(round(share))

    def get_rune_in_asset(self, val):
        """
        Get an equal amount of given value in asset
        """
        if self.is_zero():
            return 0

        share = get_share(self.asset_balance, self.rune_balance, val)
        return int(round(share))

    def get_asset_fee(self):
        """
        Calculates how much asset we need to pay for the 1 rune transaction fee
        """
        if self.is_zero():
            return 0

        return self.get_rune_in_asset(100000000)

    def sub(self, rune_amt, asset_amt):
        """
        Subtracts from pool
        """
        self.rune_balance -= rune_amt
        self.asset_balance -= asset_amt
        if self.asset_balance < 0 or self.rune_balance < 0:
            logging.error(f"Overdrawn pool: {self}")
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
            self.rune_balance, self.asset_balance, rune_amt, asset_amt,
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
        units, rune_amt, asset_amt = self._calc_unstake_units(
            staker.units, withdraw_basis_points
        )
        staker.units -= units
        self.set_staker(staker)
        self.total_units -= units
        self.sub(rune_amt, asset_amt)
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
        part1 = pool_rune + pool_asset
        part2 = stake_rune * pool_asset + pool_rune * stake_asset
        part3 = 4 * pool_rune * pool_asset
        answer = float(part1 * part2) / float(part3)
        return int(answer)

    def _calc_unstake_units(self, staker_units, withdraw_basis_points):
        """
        Calculate amount of rune/asset to unstake
        Returns staker units, rune amount, asset amount
        """
        units_to_claim = int(
            round(get_share(withdraw_basis_points, 10000, staker_units))
        )
        withdraw_rune = int(
            round(get_share(units_to_claim, self.total_units, self.rune_balance))
        )
        withdraw_asset = int(
            round(get_share(units_to_claim, self.total_units, self.asset_balance))
        )
        units_after = staker_units - units_to_claim
        if units_after < 0:
            logging.error(f"Overdrawn staker units: {self}")
            raise Exception("Overdrawn staker units")
        return units_to_claim, withdraw_rune, withdraw_asset

    def __repr__(self):
        return "<Pool %s Rune: %d | Asset: %d>" % (
            self.asset,
            self.rune_balance,
            self.asset_balance,
        )

    def __str__(self):
        return "Pool %s Rune: %d | Asset: %d" % (
            self.asset,
            self.rune_balance,
            self.asset_balance,
        )


class Staker:
    def __init__(self, address, units=0):
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
            logging.error(f"Overdrawn staker: {self}")
            raise Exception("insufficient staker units")

    def is_zero(self):
        return self.units <= 0

    def __repr__(self):
        return "<Staker %s Units: %d>" % (self.address, self.units)

    def __str__(self):
        return "Staker %s Units: %d" % (self.address, self.units)
