import time
import logging
import itertools
from copy import deepcopy

from common import (
    Transaction,
    Coin,
    Asset,
    get_share,
    HttpClient,
    Jsonable,
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

    def get_asgard_vault(self):
        return self.fetch("/thorchain/vaults/asgard")[0]

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
        self._gas_reimburse = dict()

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
                if (
                    pool.asset_balance == 0 or pool.rune_balance == 0
                ) and pool.status == "Enabled":

                    pool.status = "Bootstrap"

                    # Generate pool event with new status
                    pool_event = PoolEvent(pool.asset, pool.status)
                    event = Event("pool", Transaction.empty_txn(), None, pool_event)
                    self.events.append(event)

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

    def handle_gas(self, txns):
        """
        Subtracts gas from pool

        :param list Transaction: list outbound transaction updated with gas

        """
        gas_coins = {}
        for txn in txns:
            if txn.gas:
                for gas in txn.gas:
                    if gas.asset not in gas_coins:
                        gas_coins[gas.asset] = Coin(gas.asset)
                    gas_coins[gas.asset].amount += gas.amount

                    # generate event for GAS in transaction
                    gas_event = GasEvent(gas, "gas_spend")
                    event = Event("gas", txn, None, gas_event)
                    self.events.append(event)

        for asset, gas in gas_coins.items():
            pool = self.get_pool(gas.asset)
            # TODO: this is a hacky way to avoid
            # the problem of gas overdrawing a
            # balance. clean this up later
            if pool.asset_balance <= gas.amount:
                pool.asset_balance = 0
            else:
                pool.sub(0, gas.amount)  # subtract gas from pool

                # figure out how much rune is an equal amount to gas.amount
                rune_amt = pool.get_asset_in_rune(gas.amount)
                self.reserve -= rune_amt  # take rune from the reserve
                # add the rune amount to gas reimburse
                self._add_gas_reimburse(pool.asset, rune_amt)
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
                        if pool.rune_balance >= rune_fee:
                            pool.sub(rune_fee, 0)
                        self.set_pool(pool)
                        coin.amount -= asset_fee

                    self.reserve += rune_fee  # add to the reserve
                    if coin.amount > 0:
                        outbound.append(txn)

        # we also need to update the last event out_txs
        # with the new outbound txs only if no stake, stake events have
        # empty tx in outbound
        if self.events[-1].type != "stake":
            self.events[-1].out_txs = outbound

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

        # Generate rewards event
        reward_event = RewardEvent(0, [])
        reward_event.bond_reward = bond_reward

        if pool_reward > 0:
            # TODO: subtract any remaining gas, from the pool rewards
            if self._total_liquidity() > 0:
                for key, value in self.liquidity.items():
                    share = get_share(value, self._total_liquidity(), pool_reward)
                    pool = self.get_pool(key)
                    pool.rune_balance += share
                    self.set_pool(pool)

                    # Append pool reward to event
                    reward_event.pool_rewards.append(Coin(pool.asset, share))
            else:
                pass  # TODO: Pool Rewards are based on Depth Share
        else:
            for key, value in self.liquidity.items():
                share = get_share(staker_deficit, self._total_liquidity(), value)
                pool = self.get_pool(key)
                pool.rune_balance -= share
                self.bond_reward += share
                self.set_pool(pool)

                # Append pool reward to event
                reward_event.pool_rewards.append(Coin(pool.asset, -share))

        # generate event REWARDS
        event = Event(
            "rewards", Transaction.empty_txn(), None, reward_event, status="Success"
        )
        self.events.append(event)

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
        event = Event("refund", txn, txns, refund_event, status="Refund")
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
            logging.warning(f"Transaction memo not recognized: '{txn.memo}'")
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
                if not asset == coin.asset:
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
                if not asset == coin.asset:
                    refund_event = RefundEvent(
                        105, f"invalid stake memo:did not find {asset} "
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

        stake_units = pool.stake(txn.from_address, rune_amt, asset_amt)

        self.set_pool(pool)

        # generate event for STAKE transaction
        stake_event = StakeEvent(pool.asset, stake_units)
        event = Event("stake", txn, [Transaction.empty_txn()], stake_event)
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

        # add any rune to the reserve
        for coin in txn.coins:
            if coin.asset.is_rune():
                self.reserve += coin.amount
            else:
                coin.amount = 0

        pool = self.get_pool(asset)
        staker = pool.get_staker(txn.from_address)
        if staker.is_zero():
            # FIXME real world message
            refund_event = RefundEvent(105, "refund reason message")
            return self.refund(txn, refund_event)

        unstake_units, rune_amt, asset_amt = pool.unstake(
            txn.from_address, withdraw_basis_points
        )

        # if this is our last staker of bnb, subtract a little BNB for gas.
        if pool.total_units == 0 and pool.asset.is_bnb():
            asset_amt -= 75000
            pool.asset_balance += 75000

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
            pool.asset, unstake_units, withdraw_basis_points, 0
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
                refund_event = RefundEvent(
                    105, "checksum failed. Expected lz2zxs, got h5mz6q."
                )
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
        if source == asset:
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
                109, f"emit asset {emit.amount} less than price limit {target_trade}"
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
        trade_slip = 10000 * (x * (2 * X + x) / (X ** 2))
        return int(round(trade_slip))

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

    def handle_gas_reimburse(self):
        if self._gas_reimburse:
            gas = [
                Coin("RUNE-A1F", rune_amt)
                for (_, rune_amt) in self._gas_reimburse.items()
            ]
            reimburse_to = [asset for asset in self._gas_reimburse]
            gas_event = GasEvent(gas, "gas_reimburse", reimburse_to)
            event = Event(
                "gas", Transaction.empty_txn(), None, gas_event, status="Success"
            )
            self.events.append(event)

            self._gas_reimburse = {}

    def _add_gas_reimburse(self, asset, rune_amt):
        if asset not in self._gas_reimburse:
            self._gas_reimburse[asset] = rune_amt
        else:
            self._gas_reimburse[asset] += rune_amt


class Event(Jsonable):
    """
    Event class representing events generated by thorchain
    after handling transactions.
    """

    id_iter = itertools.count(1)

    def __init__(
        self, event_type, txn, txns_out, event, gas=None, status="Success", id=None
    ):
        self.id = int(id) if id is not None else next(Event.id_iter)
        self.type = event_type
        self.in_tx = deepcopy(txn)
        self.out_txs = txns_out
        self.gas = deepcopy(gas)
        self.event = deepcopy(event)
        self.status = status

    def __hash__(self):
        return hash(self.id)

    def __str__(self):
        return f"""
Event #{self.id} | Type {self.type.upper()} | Status {self.status} |
InTx  {self.in_tx}
OutTx {self.out_txs}
Event {self.event}
            """

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        sout_txs = self.out_txs or []
        oout_txs = other.out_txs or []
        return (
            self.type == other.type
            and self.status == other.status
            and self.in_tx == other.in_tx
            and sorted(sout_txs) == sorted(oout_txs)
            and self.event == other.event
        )

    def __lt__(self, other):
        self_coins = self.in_tx.coins or []
        other_coins = other.in_tx.coins or []
        return sorted(self_coins) < sorted(other_coins)

    @classmethod
    def from_dict(cls, value):
        event = cls(
            value["type"],
            Transaction.from_dict(value["in_tx"]),
            None,
            None,
            gas=None,
            status=value["status"],
            id=value["id"],
        )
        if "out_txs" in value and value["out_txs"]:
            event.out_txs = [Transaction.from_dict(t) for t in value["out_txs"]]
        if "gas" in value and value["gas"]:
            event.gas = [Transaction.from_dict(g) for g in value["gas"]]
        if "event" in value and value["event"]:
            if value["type"] == "refund":
                event.event = RefundEvent.from_dict(value["event"])
            if value["type"] == "add":
                event.event = AddEvent.from_dict(value["event"])
            if value["type"] == "gas":
                event.event = GasEvent.from_dict(value["event"])
            if value["type"] == "stake":
                event.event = StakeEvent.from_dict(value["event"])
            if value["type"] == "unstake":
                event.event = UnstakeEvent.from_dict(value["event"])
            if value["type"] == "swap":
                event.event = SwapEvent.from_dict(value["event"])
            if value["type"] == "reserve":
                event.event = ReserveEvent.from_dict(value["event"])
            if value["type"] == "rewards":
                event.event = RewardEvent.from_dict(value["event"])
            if value["type"] == "pool":
                event.event = PoolEvent.from_dict(value["event"])
        return event


class RefundEvent(Jsonable):
    """
    Event refund class specific to REFUND events.
    """

    def __init__(self, code, reason):
        self.code = int(code)
        self.reason = reason

    def __eq__(self, other):
        return self.code == other.code and self.reason == other.reason

    def __str__(self):
        return f'RefundEvent Code {self.code} | Reason "{self.reason}"'

    def __repr__(self):
        return f'<RefundEvent Code {self.code} | Reason "{self.reason}">'

    @classmethod
    def from_dict(cls, value):
        return cls(value["code"], value["reason"])


class PoolEvent(Jsonable):
    """
    Event pool class specific to POOL events.
    """

    def __init__(self, pool, status):
        self.pool = pool
        self.status = status

    def __eq__(self, other):
        return self.pool == other.pool and self.status == other.status

    def __str__(self):
        return f'PoolEvent Pool {self.pool} | Status "{self.status}"'

    def __repr__(self):
        return f'<PoolEvent Pool {self.pool} | Status "{self.status}">'

    @classmethod
    def from_dict(cls, value):
        return cls(value["pool"], value["status"])


class RewardEvent(Jsonable):
    """
    Event reward class specific to REWARD events.
    """

    def __init__(self, bond_reward, pool_rewards):
        self.bond_reward = int(bond_reward)
        self.pool_rewards = pool_rewards

    def __eq__(self, other):
        return self.bond_reward == other.bond_reward and sorted(
            self.pool_rewards
        ) == sorted(other.pool_rewards)

    def __str__(self):
        return (
            f"RewardEvent Bond Reward {self.bond_reward} | "
            f"Pool Rewards {self.pool_rewards}"
        )

    def __repr__(self):
        return (
            f"<RewardEvent Bond Reward {self.bond_reward} | "
            f"Pool Rewards {self.pool_rewards}>"
        )

    @classmethod
    def from_dict(cls, value):
        return cls(
            value["bond_reward"], [Coin.from_dict(c) for c in value["pool_rewards"]]
        )


class ReserveEvent(Jsonable):
    """
    Event reserve class specific to RESERVE events.
    """

    def __init__(self, address, amount):
        self.reserve_contributor = {
            "address": address,
            "amount": int(amount),
        }

    def __eq__(self, other):
        return self.reserve_contributor["amount"] == other.reserve_contributor["amount"]

    def __str__(self):
        return (
            f"ReserveEvent Address {self.reserve_contributor['address']} "
            f"| Amount {self.reserve_contributor['amount']:0,.0f}"
        )

    def __repr__(self):
        return (
            f"<ReserveEvent Address {self.reserve_contributor['address']} | "
            f"Amount {self.reserve_contributor['amount']:0,.0f}>"
        )

    @classmethod
    def from_dict(cls, value):
        return cls(
            value["reserve_contributor"]["address"],
            value["reserve_contributor"]["amount"],
        )


class GasEvent(Jsonable):
    """
    Event gas class specific to GAS events.
    """

    def __init__(self, gas, gas_type, reimburse_to=None):
        if gas and not isinstance(gas, list):
            gas = [gas]
        self.gas = gas
        self.gas_type = gas_type
        self.reimburse_to = reimburse_to

    def __eq__(self, other):
        sgas = self.gas or []
        sreimburse = self.reimburse_to or []
        ogas = other.gas or []
        oreimburse = other.reimburse_to or []
        return self.gas_type == other.gas_type and sorted(
            zip(sgas, sreimburse)
        ) == sorted(zip(ogas, oreimburse))

    def __str__(self):
        return (
            f"GasEvent {self.gas} | "
            f"Type {self.gas_type} | "
            f"Reimburse {self.reimburse_to}"
        )

    def __repr__(self):
        return (
            f"<GasEvent {self.gas} | "
            f"Type {self.gas_type} | "
            f"Reimburse {self.reimburse_to}>"
        )

    @classmethod
    def from_dict(cls, value):
        gas = [Coin.from_dict(g) for g in value["gas"]]
        reimburse_to = None
        if "reimburse_to" in value and value["reimburse_to"]:
            reimburse_to = [Asset(a) for a in value["reimburse_to"]]
        return cls(gas, value["gas_type"], reimburse_to)


class SwapEvent(Jsonable):
    """
    Event swap class specific to SWAP events.
    """

    def __init__(self, pool, price_target, trade_slip, liquidity_fee):
        self.pool = pool
        self.price_target = int(price_target)
        self.trade_slip = int(trade_slip)
        self.liquidity_fee = int(liquidity_fee)

    def __eq__(self, other):
        return (
            self.pool == other.pool
            and self.price_target == other.price_target
            and self.trade_slip == other.trade_slip
            and self.liquidity_fee == other.liquidity_fee
        )

    def __str__(self):
        return (
            f"SwapEvent Pool {self.pool} | "
            f"PriceTarget {self.price_target:0,.0f} | "
            f"TradeSlip {self.trade_slip:0,.0f} | "
            f"LiquidityFee {self.liquidity_fee:0,.0f}"
        )

    def __repr__(self):
        return (
            f"<SwapEvent Pool {self.pool} | "
            f"PriceTarget {self.price_target:0,.0f} | "
            f"TradeSlip {self.trade_slip:0,.0f} | "
            f"LiquidityFee {self.liquidity_fee:0,.0f}>"
        )

    @classmethod
    def from_dict(cls, value):
        return cls(
            value["pool"],
            value["price_target"],
            value["trade_slip"],
            value["liquidity_fee"],
        )


class StakeEvent(Jsonable):
    """
    Event stake class specific to STAKE events.
    """

    def __init__(self, asset, pool_units):
        self.pool = asset
        self.stake_units = int(pool_units)

    def __eq__(self, other):
        return self.pool == other.pool and self.stake_units == other.stake_units

    def __str__(self):
        return f"StakeEvent Pool {self.pool} | Units {self.stake_units:0,.0f}"

    def __repr__(self):
        return f"<StakeEvent Pool {self.pool} | Units {self.stake_units:0,.0f}>"

    @classmethod
    def from_dict(cls, value):
        return cls(value["pool"], value["stake_units"])


class UnstakeEvent(Jsonable):
    """
    Event unstake class specific to UNSTAKE events.
    """

    def __init__(self, asset, pool_units, basis_points, asymmetry):
        self.pool = asset
        self.stake_units = int(pool_units)
        self.basis_points = int(basis_points)
        self.asymmetry = int(float(asymmetry))

    def __eq__(self, other):
        return (
            self.pool == other.pool
            and self.stake_units == other.stake_units
            and self.basis_points == other.basis_points
            and self.asymmetry == other.asymmetry
        )

    def __str__(self):
        return (
            f"UnstakeEvent Pool {self.pool} | Units {self.stake_units:0,.0f} "
            f"| BasisPoints {self.basis_points:0,.0f} "
            f"| Asymmetry {self.asymmetry}"
        )

    def __repr__(self):
        return (
            f"<UnstakeEvent Pool {self.pool} | Units {self.stake_units} "
            f"| BasisPoints {self.basis_points} | Asymmetry {self.asymmetry}>"
        )

    @classmethod
    def from_dict(cls, value):
        return cls(
            value["pool"],
            value["stake_units"],
            value["basis_points"],
            value["asymmetry"],
        )


class AddEvent(Jsonable):
    """
    Event add class specific to ADD events.
    """

    def __init__(self, asset):
        self.pool = asset

    def __eq__(self, other):
        return self.pool == other.pool

    def __str__(self):
        return f"AddEvent Pool {self.pool}"

    def __repr__(self):
        return f"<AddEvent Pool {self.pool}>"

    @classmethod
    def from_dict(cls, value):
        return cls(value["pool"])


class Pool(Jsonable):
    def __init__(self, asset, rune_amt=0, asset_amt=0, status="Enabled"):
        self.asset = asset
        if isinstance(asset, str):
            self.asset = Asset(asset)
        self.rune_balance = rune_amt
        self.asset_balance = asset_amt
        self.total_units = 0
        self.stakers = []
        self.status = status

    def get_asset_in_rune(self, val):
        """
        Get an equal amount of given value in rune
        """
        if self.is_zero():
            return 0

        return get_share(self.rune_balance, self.asset_balance, val)

    def get_rune_in_asset(self, val):
        """
        Get an equal amount of given value in asset
        """
        if self.is_zero():
            return 0

        return get_share(self.asset_balance, self.rune_balance, val)

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
        return units

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
        return units, rune_amt, asset_amt

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
        answer = part1 * part2 / part3
        return int(answer)

    def _calc_unstake_units(self, staker_units, withdraw_basis_points):
        """
        Calculate amount of rune/asset to unstake
        Returns staker units, rune amount, asset amount
        """
        units_to_claim = get_share(withdraw_basis_points, 10000, staker_units)
        withdraw_rune = get_share(units_to_claim, self.total_units, self.rune_balance)
        withdraw_asset = get_share(units_to_claim, self.total_units, self.asset_balance)
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


class Staker(Jsonable):
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
