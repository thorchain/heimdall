import base64
import logging
import itertools
import threading
import websocket
import json
from copy import deepcopy

from utils.common import (
    Transaction,
    Coin,
    Asset,
    get_share,
    HttpClient,
    Jsonable,
    get_rune_asset,
)

from chains.aliases import get_alias, get_alias_address, get_aliases
from chains.bitcoin import Bitcoin
from chains.ethereum import Ethereum
from tenacity import retry, stop_after_delay, wait_fixed

RUNE = get_rune_asset()
SUBSCRIBE_BLOCK = {"jsonrpc": "2.0", "id": 0, "method": "subscribe", "params": {"query": "tm.event='NewBlock'"}}
SUBSCRIBE_TX = {"jsonrpc": "2.0", "id": 0, "method": "subscribe", "params": {"query": "tm.event='Tx'"}}


class ThorchainClient(HttpClient):
    """
    A client implementation to thorchain API
    """

    def __init__(self, api_url, websocket_url=None):
        super().__init__(api_url)

        self.wait_for_node()

        if websocket_url:
            self.ws = websocket.WebSocketApp(
                websocket_url,
                on_open=self.ws_open,
                on_error=self.ws_error,
                on_message=self.ws_message,
            )
            self.events = []
            threading.Thread(target=self.ws.run_forever, daemon=True).start()

    @retry(stop=stop_after_delay(30), wait=wait_fixed(1))
    def wait_for_node(self):
        current_height = self.get_block_height()
        if current_height < 1:
            logging.warning("Thorchain starting, waiting")
            raise Exception

    def ws_open(self):
        """
        Websocket connection open, subscribe to events
        """
        logging.debug("websocket opened")
        self.ws.send(json.dumps(SUBSCRIBE_BLOCK))
        self.ws.send(json.dumps(SUBSCRIBE_TX))

    def ws_message(self, msg):
        """
        Websocket message handler
        """
        try:
            msg = json.loads(msg)
            logging.debug(f"websocket msg: {msg}")
            if "data" not in msg["result"]:
                return
            event_category = msg["result"]["data"]["type"]
            value = msg["result"]["data"]["value"]
            if "NewBlock" in event_category:
                if "events" not in value["result_end_block"]:
                    return
                events = value["result_end_block"]["events"]
                block_height = value["block"]["header"]["height"]
                self.process_events(events, block_height, "block")
            if "Tx" in event_category:
                events = value["TxResult"]["result"]["events"]
                block_height = value["TxResult"]["height"]
                self.process_events(events, block_height, "tx")
        except Exception as e:
            logging.error(f"Message: {msg} Exception: {e}")

    def process_events(self, events, block_height, category):
        new_events = []
        for event in events:
            if event["type"] == "message":
                continue
            self.decode_event(event)
            evt = Event(
                event["type"],
                event["attributes"],
                block_height,
                category,
            )
            new_events.append(evt)
        new_events += self.events
        self.sort_events(new_events)
        self.events = new_events

    @classmethod
    def sort_events(self, events):
        """
        Sort events by block height and category
        with block events after tx events
        """
        return events.sort(key=lambda e: (
            int(e.block_height),
            (e.category == "block")
        ))

    def decode_event(self, event):
        attributes = []
        for attr in event["attributes"]:
            key = base64.b64decode(attr["key"]).decode("utf-8")
            value = base64.b64decode(attr["value"]).decode("utf-8")
            attributes.append({key: value})
        event["attributes"] = attributes

    def ws_error(self, error):
        """
        Websocket error handler
        """
        logging.error(error)
        raise Exception("thorchain websocket error")

    def get_block_height(self):
        """
        Get the current block height of mock binance
        """
        data = self.fetch("/thorchain/lastblock")
        return int(data["thorchain"])

    def get_vault_address(self, chain):
        data = self.fetch("/thorchain/pool_addresses")
        for d in data["current"]:
            if chain == d["chain"]:
                return d["address"]
        return "address not found"

    def get_vault_pubkey(self):
        data = self.fetch("/thorchain/pool_addresses")
        return data["current"][0]["pub_key"]

    def get_vault_data(self):
        return self.fetch("/thorchain/vault")

    def get_asgard_vaults(self):
        return self.fetch("/thorchain/vaults/asgard")

    def get_pools(self):
        return self.fetch("/thorchain/pools")


class ThorchainState:
    """
    A complete implementation of the thorchain logic/behavior
    """

    rune_fee = 100000000

    def __init__(self):
        self.pools = []
        self.events = []
        self.reserve = 0
        self.liquidity = {}
        self.total_bonded = 0
        self.bond_reward = 0
        self._gas_reimburse = dict()
        self.vault_pubkey = None

    def set_vault_pubkey(self, pubkey):
        """
        Set vault pubkey bech32 encoded, used to generate hashes
        to order broadcast of outbound transactions.
        """
        self.vault_pubkey = pubkey

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
                    event = Event(
                        "pool", [{"pool": pool.asset}, {"pool_status": pool.status}]
                    )
                    self.events.append(event)

                self.pools[i] = pool
                return

        self.pools.append(pool)

    def handle_gas(self, txns):
        """
        Subtracts gas from pool

        :param list Transaction: list outbound transaction updated with gas

        """
        gas_coins = {}
        gas_coin_count = {}

        for txn in txns:
            if txn.gas:
                for gas in txn.gas:
                    if gas.asset not in gas_coins:
                        gas_coins[gas.asset] = Coin(gas.asset)
                        gas_coin_count[gas.asset] = 0
                    gas_coins[gas.asset].amount += gas.amount
                    gas_coin_count[gas.asset] += 1

        if not len(gas_coins.items()):
            return

        gas_pools = []

        for asset, gas in gas_coins.items():
            pool = self.get_pool(gas.asset)
            # TODO: this is a hacky way to avoid
            # the problem of gas overdrawing a
            # balance. clean this up later
            if pool.asset_balance <= gas.amount:
                pool.asset_balance = 0
                rune_amt = 0
            else:
                # figure out how much rune is an equal amount to gas.amount
                rune_amt = pool.get_asset_in_rune(gas.amount)
                self.reserve -= rune_amt  # take rune from the reserve

                pool.add(rune_amt, 0)  # replenish gas costs with rune
                pool.sub(0, gas.amount)  # subtract gas from pool

            self.set_pool(pool)

            # add gas event
            event = Event(
                "gas",
                [
                    {"asset": asset},
                    {"asset_amt": gas.amount},
                    {"rune_amt": rune_amt},
                    {"transaction_count": gas_coin_count[asset]},
                ],
            )
            self.events.append(event)

    def handle_fee(self, in_tx, txns):
        """
        Subtract transaction fee from given transactions
        """
        outbound = []
        if not isinstance(txns, list):
            txns = [txns]

        for txn in txns:
            for coin in txn.coins:
                if coin.is_rune():
                    # deduct 1 rune transaction fee
                    coin.amount -= self.rune_fee

                    # add to the reserve
                    self.reserve += self.rune_fee

                    if coin.amount > 0:
                        outbound.append(txn)

                    # add fee event
                    event = Event(
                        "fee",
                        [
                            {"tx_id": in_tx.id},
                            {"coins": f"{self.rune_fee} {coin.asset}"},
                            {"pool_deduct": 0},
                        ],
                    )
                    self.events.append(event)

                else:
                    pool = self.get_pool(coin.asset)

                    if not pool.is_zero():
                        # default to zero if pool is empty
                        asset_fee = pool.get_asset_fee()

                        pool.add(0, asset_fee)
                        if pool.rune_balance >= self.rune_fee:
                            pool.sub(self.rune_fee, 0)
                        self.set_pool(pool)
                        coin.amount -= asset_fee

                        # add fee event
                        event = Event(
                            "fee",
                            [
                                {"tx_id": in_tx.id},
                                {"coins": f"{asset_fee} {coin.asset}"},
                                {"pool_deduct": self.rune_fee},
                            ],
                        )
                        self.events.append(event)

                    # add to the reserve
                    self.reserve += self.rune_fee
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

        # get the total staked
        # TODO: skip non-enabled pools
        total_staked = 0
        for pool in self.pools:
            total_staked += pool.rune_balance

        if total_staked == 0:  # nothing staked, no rewards
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
        reward_event = Event("rewards", [{"bond_reward": bond_reward}])

        if pool_reward > 0:
            # TODO: subtract any remaining gas, from the pool rewards
            if self._total_liquidity() > 0:
                for key, value in self.liquidity.items():
                    share = get_share(value, self._total_liquidity(), pool_reward)
                    pool = self.get_pool(key)
                    pool.rune_balance += share
                    self.set_pool(pool)

                    # Append pool reward to event
                    reward_event.attributes.append({pool.asset: str(share)})
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
                reward_event.attributes.append({pool.asset: str(-share)})

        # generate event REWARDS
        self.events.append(reward_event)

        # clear summed liquidity fees
        self.liquidity = {}

    def refund(self, txn, code, reason):
        """
        Returns a list of refund transactions based on given txn
        """
        txns = []
        for coin in txn.coins:
            if not coin.is_rune():
                pool = self.get_pool(coin.asset)
                if pool.rune_balance == 0:
                    continue  # no pool exists, skip it
            txns.append(
                Transaction(
                    txn.chain,
                    txn.to_address,
                    txn.from_address,
                    [coin],
                    f"REFUND:{txn.id}",
                )
            )

        # generate event REFUND for the transaction
        event = Event(
            "refund",
            [
                {"code": code},
                {"reason": reason},
                *txn.get_attributes(),
            ],
        )
        self.events.append(event)
        return txns

    def generate_outbound_events(self, in_tx, txns):
        """
        Generate outbound events for txns
        """
        for txn in txns:
            event = Event(
                "outbound", [{"in_tx_id": in_tx.id}, *txn.get_attributes()]
            )
            self.events.append(event)

    def order_outbound_txns(self, txns):
        """
        Sort txns by tx custom hash function to replicate real thorchain order
        """
        if txns:
            txns.sort(key=lambda tx: tx.custom_hash(self.vault_pubkey))

    def handle(self, txn):
        """
        This is a router that sends a transaction to the correct handler.
        It will return transactions to send

        :param txn: txn IN
        :returns: txs OUT

        """
        tx = deepcopy(txn)  # copy of transaction

        if tx.chain == "THOR":
            self.reserve += 100000000
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
            if tx.memo == "":
                return self.refund(tx, 105, "memo can't be empty")
            return self.refund(tx, 105, f"invalid tx type: {tx.memo}")

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
        event = Event(
            "reserve",
            [
                {"contributor_address": txn.from_address},
                {"amount": amount},
                *txn.get_attributes(),
            ],
        )
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
                return self.refund(txn, 105, "memo can't be empty")
            return self.refund(txn, 105, f"invalid tx type: {txn.memo}")

        asset = Asset(parts[1])

        # check that we have one rune and one asset
        if len(txn.coins) > 2:
            # FIXME real world message
            return self.refund(txn, 105, "refund reason message")

        for coin in txn.coins:
            if not coin.is_rune():
                if not asset == coin.asset:
                    # mismatch coin asset and memo
                    return self.refund(txn, 105, "Invalid symbol")

        pool = self.get_pool(asset)
        for coin in txn.coins:
            if coin.is_rune():
                pool.add(coin.amount, 0)
            else:
                pool.add(0, coin.amount)

        self.set_pool(pool)

        # generate event for ADD transaction
        event = Event(
            "add",
            [
                {"pool": pool.asset},
                *txn.get_attributes(),
            ],
        )
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
                return self.refund(txn, 105, "memo can't be empty")
            return self.refund(txn, 105, f"invalid tx type: {txn.memo}")

            # empty asset
        if parts[1] == "":
            return self.refund(txn, 105, "Invalid symbol")

        asset = Asset(parts[1])

        # cant have rune memo
        if asset.is_rune():
            return self.refund(txn, 105, "invalid stake memo:invalid pool asset")

        # check that we have one rune and one asset
        if len(txn.coins) > 2:
            # FIXME real world message
            return self.refund(txn, 105, "refund reason message")

        # check for mismatch coin asset and memo
        for coin in txn.coins:
            if not coin.is_rune():
                if not asset == coin.asset:
                    return self.refund(
                        txn, 105, f"invalid stake memo:did not find {asset} "
                    )

        if len(parts) < 3 and asset.get_chain() != RUNE.get_chain():
            reason = (
                f"invalid stake. Cannot stake to a non {RUNE.get_chain()}-based",
                f" pool without providing an associated address",
            )
            return self.refund(txn, 105, reason)

        pool = self.get_pool(asset)
        rune_amt = 0
        asset_amt = 0
        for coin in txn.coins:
            if coin.is_rune():
                rune_amt = coin.amount
            else:
                asset_amt = coin.amount

        # check address to stake to from memo
        address = txn.from_address
        if txn.chain != RUNE.get_chain() and len(parts) > 2:
            address = parts[2]

        stake_units = pool.stake(address, rune_amt, asset_amt, asset)

        self.set_pool(pool)

        # generate event for STAKE transaction
        event = Event(
            "stake",
            [
                {"pool": pool.asset},
                {"stake_units": stake_units},
                *txn.get_attributes(),
            ],
        )
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
                return self.refund(txn, 105, "memo can't be empty")
            return self.refund(txn, 105, f"invalid tx type: {txn.memo}")

        # get withdrawal basis points, if it exists in the memo
        if len(parts) >= 3:
            withdraw_basis_points = int(parts[2])

        # empty asset
        if parts[1] == "":
            return self.refund(txn, 105, "Invalid symbol")

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
            return self.refund(txn, 105, "refund reason message")

        # calculate gas prior to update pool in case we empty the pool
        # and need to subtract
        gas = None
        if asset.get_chain() == "BTC":
            gas = [Bitcoin._calculate_gas(pool, txn)]

        if asset.get_chain() == "ETH":
            gas = [Ethereum._calculate_gas(pool, txn)]

        unstake_units, rune_amt, asset_amt = pool.unstake(
            txn.from_address, withdraw_basis_points
        )

        # if this is our last staker of bnb, subtract a little BNB for gas.
        if pool.total_units == 0:
            if pool.asset.is_bnb():
                fee_amt = 37500
                if RUNE.get_chain() == "BNB":
                    fee_amt *= 2
                asset_amt -= fee_amt
                pool.asset_balance += fee_amt
            elif pool.asset.is_btc() or pool.asset.is_eth():
                asset_amt -= gas[0].amount
                pool.asset_balance += gas[0].amount

        self.set_pool(pool)

        # get from address VAULT cross chain
        from_address = txn.to_address
        if from_address != "VAULT":  # don't replace for unit tests
            from_alias = get_alias(txn.chain, from_address)
            from_address = get_alias_address(asset.get_chain(), from_alias)

        # get to address cross chain
        to_address = txn.from_address
        if to_address not in get_aliases():  # don't replace for unit tests
            to_alias = get_alias(txn.chain, to_address)
            to_address = get_alias_address(asset.get_chain(), to_alias)

        out_txns = [
            Transaction(
                RUNE.get_chain(),
                txn.to_address,
                txn.from_address,
                [Coin(RUNE, rune_amt)],
                f"OUTBOUND:{txn.id.upper()}",
            ),
            Transaction(
                asset.get_chain(),
                from_address,
                to_address,
                [Coin(asset, asset_amt)],
                f"OUTBOUND:{txn.id.upper()}",
                gas=gas,
            ),
        ]

        # generate event for UNSTAKE transaction
        event = Event(
            "unstake",
            [
                {"pool": pool.asset},
                {"stake_units": unstake_units},
                {"basis_points": withdraw_basis_points},
                {"asymmetry": "0.000000000000000000"},
                *txn.get_attributes(),
            ],
        )
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
                return self.refund(txn, 105, "memo can't be empty")
            return self.refund(txn, 105, f"invalid tx type: {txn.memo}")

        address = txn.from_address
        # check address to send to from memo
        if len(parts) > 2:
            address = parts[2]
            # checking if address is for mainnet, not testnet
            if address.lower().startswith("bnb"):
                reason = f"address format not supported: {address}"
                return self.refund(txn, 105, reason)

        # get trade target, if exists
        target_trade = 0
        if len(parts) > 3:
            target_trade = int(parts[3] or "0")

        asset = Asset(parts[1])

        # check that we have one coin
        if len(txn.coins) != 1:
            reason = "invalid swap memo:not expecting multiple coins in a swap"
            return self.refund(txn, 105, reason)

        source = txn.coins[0].asset
        target = asset

        # refund if we're trying to swap with the coin we given ie swapping bnb
        # with bnb
        if source == asset:
            reason = f"invalid swap memo:swap from {source} to {target} is noop, refund"
            return self.refund(txn, 105, reason)

        pools = []

        in_txn = txn

        if not txn.coins[0].is_rune() and not asset.is_rune():
            # its a double swap
            pool = self.get_pool(source)
            if pool.is_zero():
                # FIXME real world message
                return self.refund(txn, 105, "refund reason message")

            emit, liquidity_fee, liquidity_fee_in_rune, trade_slip, pool = self.swap(
                txn.coins[0], RUNE
            )
            if str(pool.asset) not in self.liquidity:
                self.liquidity[str(pool.asset)] = 0
            self.liquidity[str(pool.asset)] += liquidity_fee_in_rune

            # here we copy the txn to break references cause
            # the tx is split in 2 events and gas is handled only once
            in_txn = deepcopy(txn)

            # generate event for SWAP transaction
            event = Event(
                "swap",
                [
                    {"pool": pool.asset},
                    {"price_target": 0},
                    {"trade_slip": trade_slip},
                    {"liquidity_fee": liquidity_fee},
                    {"liquidity_fee_in_rune": liquidity_fee_in_rune},
                    *in_txn.get_attributes(),
                ],
            )
            self.events.append(event)

            # and we remove the gas on in_txn for the next event so we don't
            # have it twice
            in_txn.gas = None

            pools.append(pool)
            in_txn.coins[0] = emit
            source = RUNE
            target = asset

        # set asset to non-rune asset
        asset = source
        if asset.is_rune():
            asset = target

        pool = self.get_pool(asset)
        if pool.is_zero():
            # FIXME real world message
            return self.refund(in_txn, 105, "refund reason message: pool is zero")

        emit, liquidity_fee, liquidity_fee_in_rune, trade_slip, pool = self.swap(
            in_txn.coins[0], asset
        )
        pools.append(pool)

        # check emit is non-zero and is not less than the target trade
        if emit.is_zero() or (emit.amount < target_trade):
            reason = f"emit asset {emit.amount} less than price limit {target_trade}"
            return self.refund(in_txn, 108, reason)

        if str(pool.asset) not in self.liquidity:
            self.liquidity[str(pool.asset)] = 0
        self.liquidity[str(pool.asset)] += liquidity_fee_in_rune

        # save pools
        for pool in pools:
            self.set_pool(pool)

        # get from address VAULT cross chain
        from_address = in_txn.to_address
        if from_address != "VAULT":  # don't replace for unit tests
            from_alias = get_alias(in_txn.chain, from_address)
            from_address = get_alias_address(target.get_chain(), from_alias)

        gas = None

        # calculate gas if BTC
        if target.get_chain() == "BTC":
            gas = [Bitcoin._calculate_gas(pool, txn)]

        # calculate gas if ETH
        if target.get_chain() == "ETH":
            gas = [Ethereum._calculate_gas(pool, txn)]

        out_txns = [
            Transaction(
                target.get_chain(),
                from_address,
                address,
                [emit],
                f"OUTBOUND:{txn.id.upper()}",
                gas=gas,
            )
        ]

        # generate event for SWAP transaction
        event = Event(
            "swap",
            [
                {"pool": pool.asset},
                {"price_target": target_trade},
                {"trade_slip": trade_slip},
                {"liquidity_fee": liquidity_fee},
                {"liquidity_fee_in_rune": liquidity_fee_in_rune},
                *in_txn.get_attributes(),
            ],
        )
        self.events.append(event)

        return out_txns

    def swap(self, coin, asset):
        """
        Does a swap returning amount of coins emitted and new pool

        :param Coin coin: coin sent to swap
        :param Asset asset: target asset
        :returns: list of events
            - emit (int) - number of coins to be emitted for the swap
            - liquidity_fee (int) - liquidity fee
            - liquidity_fee_in_rune (int) - liquidity fee in rune
            - trade_slip (int) - trade slip
            - pool (Pool) - pool with new values

        """
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
        liquidity_fee_in_rune = liquidity_fee
        if coin.is_rune():
            liquidity_fee_in_rune = pool.get_asset_in_rune(liquidity_fee)

        # calculate trade slip
        trade_slip = self._calc_trade_slip(X, x)

        # if we emit zero, return immediately
        if emit == 0:
            return Coin(asset, emit), 0, 0, 0, pool

        newPool = deepcopy(pool)  # copy of pool
        if coin.is_rune():
            newPool.add(x, 0)
            newPool.sub(0, emit)
            emit = Coin(asset, emit)
        else:
            newPool.add(0, x)
            newPool.sub(emit, 0)
            emit = Coin(RUNE, emit)

        return emit, liquidity_fee, liquidity_fee_in_rune, trade_slip, newPool

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


class Event(Jsonable):
    """
    Event class representing events generated by thorchain
    using tendermint sdk events
    """

    def __init__(
        self,
        event_type,
        attributes,
        block_height=None,
        category=None,
    ):
        self.type = event_type
        for attr in attributes:
            for key, value in attr.items():
                attr[key] = str(value)
        self.attributes = attributes
        self.block_height = block_height
        self.category = category

    def __str__(self):
        attrs = " ".join(map(str, self.attributes))
        return f"Event {self.type} | {attrs}"

    def __hash__(self):
        attrs = sorted(self.attributes, key=lambda x: sorted(x.items()))
        if self.type == "outbound":
            attrs = [a for a in attrs if list(a.keys())[0] != "id"]
        return hash(str(attrs))

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        return (self.type, hash(self)) == (other.type, hash(other))

    def __lt__(self, other):
        return (self.type, hash(self)) < (other.type, hash(other))

    def get(self, attr):
        for a in self.attributes:
            if list(a.keys())[0] == attr:
                return a[attr]
        return None


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

    def stake(self, address, rune_amt, asset_amt, asset):
        """
        Stake rune/asset for an address
        """
        staker = self.get_staker(address)

        # handle cross chain stake
        if not asset.get_chain() == RUNE.get_chain():
            if asset_amt == 0:
                staker.pending_rune += rune_amt
                self.set_staker(staker)
                return 0

            rune_amt += staker.pending_rune
            staker.pending_rune = 0

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
        if part3 == 0:
            return 0
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
        self.pending_rune = 0

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
