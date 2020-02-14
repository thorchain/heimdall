import argparse

from chains import Binance, MockBinance
from thorchain import ThorchainState, ThorchainClient

from common import Transaction, Coin, Asset

# A list of smoke test transaction, [inbound txn, expected # of outbound txns]
txns = [
    # Seeding funds to various accounts
    [
        Transaction(
            Binance.chain,
            "MASTER",
            "MASTER",
            [Coin("BNB", 49730000), Coin("RUNE-A1F", 100000000000), Coin("LOK-3C0", 0)],
            "SEED",
        ),
        0,
    ],
    [
        Transaction(
            Binance.chain,
            "MASTER",
            "USER-1",
            [
                Coin("BNB", 50000000),
                Coin("RUNE-A1F", 50000000000),
                Coin("LOK-3C0", 50000000000),
            ],
            "SEED",
        ),
        0,
    ],
    [
        Transaction(
            Binance.chain,
            "MASTER",
            "STAKER-1",
            [
                Coin("BNB", 200000000),
                Coin("RUNE-A1F", 100000000000),
                Coin("LOK-3C0", 40000000000),
            ],
            "SEED",
        ),
        0,
    ],
    [
        Transaction(
            Binance.chain,
            "MASTER",
            "STAKER-2",
            [
                Coin("BNB", 200000000),
                Coin("RUNE-A1F", 50000000000),
                Coin("LOK-3C0", 10000000000),
            ],
            "SEED",
        ),
        0,
    ],
    # Staking
    [
        Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "STAKE:BNB.BNB",
        ),
        0,
    ],
    [
        Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("LOK-3C0", 40000000000), Coin("RUNE-A1F", 50000000000)],
            "STAKE:BNB.LOK-3C0",
        ),
        0,
    ],
    [
        Transaction(
            Binance.chain,
            "STAKER-2",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "",
        ),
        2,
    ],
    [
        Transaction(
            Binance.chain,
            "STAKER-2",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "ABDG?",
        ),
        2,
    ],
    [
        Transaction(
            Binance.chain,
            "STAKER-2",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "STAKE:",
        ),
        2,
    ],
    [
        Transaction(
            Binance.chain,
            "STAKER-2",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "STAKE:BNB.TCAN-014",
        ),
        2,
    ],
    [
        Transaction(
            Binance.chain,
            "STAKER-2",
            "VAULT",
            [Coin("BNB", 150000000), Coin("RUNE-A1F", 50000000000)],
            "STAKE:RUNE-A1F",
        ),
        2,
    ],
    [
        Transaction(
            Binance.chain, "STAKER-2", "VAULT", [Coin("BNB", 30000000)], "STAKE:BNB.BNB"
        ),
        0,
    ],
    [
        Transaction(
            Binance.chain,
            "STAKER-2",
            "VAULT",
            [Coin("RUNE-A1F", 10000000000)],
            "STAKE:BNB.BNB",
        ),
        0,
    ],
    [
        Transaction(
            Binance.chain,
            "STAKER-2",
            "VAULT",
            [Coin("BNB", 90000000), Coin("RUNE-A1F", 30000000000)],
            "STAKE:BNB.BNB",
        ),
        0,
    ],
    # Adding
    [
        Transaction(
            Binance.chain,
            "STAKER-2",
            "VAULT",
            [Coin("BNB", 30000000), Coin("RUNE-A1F", 5000000000)],
            "ADD:BNB.BNB",
        ),
        0,
    ],
    # Misc
    [
        Transaction(
            Binance.chain, "USER-1", "VAULT", [Coin("RUNE-A1F", 100000000)], " "
        ),
        1,
    ],
    [
        Transaction(
            Binance.chain, "USER-1", "VAULT", [Coin("RUNE-A1F", 100000000)], "ABDG?"
        ),
        1,
    ],
    # Swaps
    [
        Transaction(Binance.chain, "USER-1", "VAULT", [Coin("BNB", 1)], "SWAP:BNB.BNB"),
        1,
    ],
    [
        Transaction(
            Binance.chain, "USER-1", "VAULT", [Coin("BNB", 30000000)], "SWAP:BNB.BNB"
        ),
        1,
    ],
    [
        Transaction(
            Binance.chain,
            "USER-1",
            "VAULT",
            [Coin("BNB", 30000000), Coin("RUNE-A1F", 100000000)],
            "SWAP:BNB.BNB",
        ),
        1,
    ],
    [
        Transaction(
            Binance.chain, "USER-1", "VAULT", [Coin("RUNE-A1F", 1)], "SWAP:BNB.BNB"
        ),
        1,
    ],
    [
        Transaction(
            Binance.chain,
            "USER-1",
            "VAULT",
            [Coin("RUNE-A1F", 10000000000)],
            "SWAP:BNB.BNB::26572599",
        ),
        1,
    ],
    [
        Transaction(
            Binance.chain,
            "USER-1",
            "VAULT",
            [Coin("RUNE-A1F", 10000000000)],
            "SWAP:BNB.BNB",
        ),
        1,
    ],
    [
        Transaction(
            Binance.chain,
            "USER-1",
            "VAULT",
            [Coin("BNB", 10000000)],
            "SWAP:BNB.RUNE-A1F",
        ),
        1,
    ],
    [
        Transaction(
            Binance.chain,
            "USER-1",
            "VAULT",
            [Coin("RUNE-A1F", 10000000000)],
            "SWAP:BNB.BNB:STAKER-1:23853375",
        ),
        1,
    ],
    [
        Transaction(
            Binance.chain,
            "USER-1",
            "VAULT",
            [Coin("RUNE-A1F", 10000000000)],
            "SWAP:BNB.BNB:STAKER-1:22460886",
        ),
        1,
    ],
    [
        Transaction(
            Binance.chain,
            "USER-1",
            "VAULT",
            [Coin("BNB", 10000000)],
            "SWAP:BNB.RUNE-A1F:bnbSTAKER-1",
        ),
        1,
    ],
    [
        Transaction(
            Binance.chain,
            "USER-1",
            "VAULT",
            [Coin("LOK-3C0", 5000000000)],
            "SWAP:BNB.RUNE-A1F",
        ),
        1,
    ],
    [
        Transaction(
            Binance.chain,
            "USER-1",
            "VAULT",
            [Coin("RUNE-A1F", 5000000000)],
            "SWAP:BNB.LOK-3C0",
        ),
        1,
    ],
    [
        Transaction(
            Binance.chain,
            "USER-1",
            "VAULT",
            [Coin("LOK-3C0", 5000000000)],
            "SWAP:BNB.BNB",
        ),
        1,
    ],
    [
        Transaction(
            Binance.chain, "USER-1", "VAULT", [Coin("BNB", 5000000)], "SWAP:BNB.LOK-3C0"
        ),
        1,
    ],
    # Unstaking (withdrawing)
    [
        Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 1)],
            "WITHDRAW:BNB.BNB:5000",
        ),
        2,
    ],
    [
        Transaction(
            Binance.chain, "STAKER-1", "VAULT", [Coin("BNB", 1)], "WITHDRAW:BNB.LOK-3C0"
        ),
        2,
    ],
    [
        Transaction(
            Binance.chain,
            "STAKER-1",
            "VAULT",
            [Coin("BNB", 1)],
            "WITHDRAW:BNB.BNB:10000",
        ),
        2,
    ],
    [
        Transaction(
            Binance.chain, "STAKER-2", "VAULT", [Coin("BNB", 1)], "WITHDRAW:BNB.BNB"
        ),
        2,
    ],
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binance", default="http://localhost:26660", help="Mock binance server"
    )
    parser.add_argument(
        "--thorchain", default="http://localhost:1317", help="Thorchain API url"
    )
    parser.add_argument(
        "--generate-balances", default=False, type=bool, help="Generate balances (bool)"
    )
    parser.add_argument(
        "--fast-fail", default=False, type=bool, help="Generate balances (bool)"
    )

    args = parser.parse_args()

    smoker = Smoker(
        args.binance, args.thorchain, txns, args.generate_balances, args.fast_fail
    )
    smoker.run()


class Smoker:
    def __init__(self, bnb, thor, txns=txns, gen_balances=False, fast_fail=False):
        self.binance = Binance()
        self.thorchain = ThorchainState()

        self.txns = txns

        self.thorchain_client = ThorchainClient(thor)
        vault_address = self.thorchain_client.get_vault_address()

        self.mock_binance = MockBinance(bnb)
        self.mock_binance.set_vault_address(vault_address)

        self.generate_balances = gen_balances
        self.fast_fail = fast_fail

    def run(self):
        for i, unit in enumerate(self.txns):
            # get transaction and expected number of outbound transactions
            txn, out = unit
            print("{} {}".format(i, txn))

            if txn.memo == "SEED":
                self.binance.seed(txn.toAddress, txn.coins)
                self.mock_binance.seed(txn.toAddress, txn.coins)
                continue

            self.binance.transfer(txn)  # send transfer on binance chain
            outbounds = self.thorchain.handle(txn)  # process transaction in thorchain
            for outbound in outbounds:
                gas = self.binance.transfer(
                    outbound
                )  # send outbound txns back to Binance
                self.thorchain.handle_gas(gas)  # subtract gas from pool(s)

            # update memo with actual address (over alias name)
            for name, addr in self.mock_binance.aliases.items():
                txn.memo = txn.memo.replace(name, addr)

            self.mock_binance.transfer(txn)  # trigger mock Binance transaction
            self.mock_binance.wait_for_blocks(out)
            self.thorchain_client.wait_for_blocks(
                1
            )  # wait an additional block to pick up gas

            # compare simulation pools vs real pools
            real_pools = self.thorchain_client.get_pools()
            for rpool in real_pools:
                spool = self.thorchain.get_pool(Asset(rpool["asset"]))
                if int(spool.rune_balance) != int(rpool["balance_rune"]):
                    raise Exception(
                        "bad pool rune balance: {} {} != {}".format(
                            rpool["asset"], spool.rune_balance, rpool["balance_rune"]
                        )
                    )
                if int(spool.asset_balance) != int(rpool["balance_asset"]):
                    raise Exception(
                        "bad pool asset balance: {} {} != {}".format(
                            rpool["asset"], spool.asset_balance, rpool["balance_asset"]
                        )
                    )

            # compare simulation binance vs mock binance
            mockAccounts = self.mock_binance.accounts()
            for macct in mockAccounts:
                for name, address in self.mock_binance.aliases.items():
                    if name == "MASTER":
                        continue  # don't care to compare MASTER account
                    if address == macct["address"]:
                        sacct = self.binance.get_account(name)
                        for bal in macct["balances"]:
                            coin = Coin(bal["denom"], sacct.get(bal["denom"]))
                            if not coin.is_equal(
                                Coin(bal["denom"], int(bal["amount"]))
                            ):
                                raise Exception(
                                    "bad binance balance: {} {} != {}".format(
                                        bal["denom"], bal["amount"], coin
                                    )
                                )


if __name__ == "__main__":
    main()
