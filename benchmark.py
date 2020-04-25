import argparse
import logging
import os
import time
import sys
import json
from tqdm import tqdm

from chains.binance import MockBinance
from thorchain import ThorchainState, ThorchainClient
from common import Transaction, Coin, Asset
from chains.aliases import get_alias

# Init logging
logging.basicConfig(
    format="%(asctime)s | %(levelname).4s | %(message)s",
    level=os.environ.get("LOGLEVEL", "INFO"),
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binance", default="http://localhost:26660", help="Mock binance server"
    )
    parser.add_argument(
        "--thorchain", default="http://localhost:1317", help="Thorchain API url"
    )
    parser.add_argument(
        "--num-swaps", type=int, default=10, help="Number of swaps to perform"
    )
    args = parser.parse_args()

    benchie = Benchie(
        args.binance,
        args.thorchain,
        args.num_swaps,
    )
    try:
        benchie.run()
    except Exception as e:
        logging.fatal(e)
        sys.exit(1)


class Benchie:
    def __init__(
        self,
        bnb,
        thor,
        num_swaps,
    ):
        self.thorchain = ThorchainState()

        self.thorchain_client = ThorchainClient(thor)
        vault_address = self.thorchain_client.get_vault_address()
        vault_pubkey = self.thorchain_client.get_vault_pubkey()

        self.thorchain.set_vault_pubkey(vault_pubkey)

        self.mock_binance = MockBinance(bnb)
        self.mock_binance.set_vault_address(vault_address)

        self.num_swaps = num_swaps

        time.sleep(5)  # give thorchain extra time to start the blockchain

    def error(self, err):
        self.exit = 1
        if self.fast_fail:
            raise Exception(err)
        else:
            logging.error(err)

    def run(self):
        logging.info(f">>> Starting benchmark... (Swaps: {self.num_swaps})")
        logging.info(">>> setting up...")
        # seed staker
        self.mock_binance.transfer(
            Transaction("BNB", get_alias("BNB", "MASTER"), get_alias("BNB", "STAKER-1"), [
                Coin("BNB", self.num_swaps * 100 * Coin.ONE),
                Coin("RUNE-A1F", self.num_swaps * 100 * Coin.ONE),
            ])
        )

        # seed swapper
        self.mock_binance.transfer(
            Transaction("BNB", get_alias("BNB", "MASTER"), get_alias("BNB", "USER-1"), [
                Coin("BNB", self.num_swaps * 100 * Coin.ONE),
                Coin("RUNE-A1F", self.num_swaps * 100 * Coin.ONE),
            ])
        )

        # stake BNB
        #self.mock_binance.transfer(
            #Transaction("BNB", get_alias("BNB", "STAKER-1"), get_alias("BNB", "VAULT"), [
                #Coin("BNB", self.num_swaps * 100 * Coin.ONE),
                #Coin("RUNE-A1F", self.num_swaps * 100 * Coin.ONE),
            #], memo="STAKE:BNB.BNB")
        #)
        
        time.sleep(5)  # give thorchain extra time to start the blockchain

        logging.info("<<< done.")
        logging.info(">>> compiling transactions...")
        txns = []
        memo = "STAKE:BNB.BNB"
        for x in range(0, self.num_swaps):
            txns.append(
                Transaction("BNB", get_alias("BNB", "USER-1"), get_alias("BNB", "VAULT"), [
                    Coin("RUNE-A1F", 10 * Coin.ONE),
                    Coin("BNB", 10 * Coin.ONE),
                ], memo=memo)
            )

        logging.info("<<< done.")
        logging.info(">>> broadcasting transactions...")
        self.mock_binance.transfer(txns)
        logging.info("<<< done.")

        logging.info(">>> timing for thorchain...")
        start_block_height = self.thorchain_client.get_block_height()
        t1 = time.time()
        completed = 0
        last_event_id = 1

        pbar = tqdm(total=self.num_swaps)
        while completed < self.num_swaps:
            events = self.thorchain_client.get_events(last_event_id)
            if len(events) == 0:
                time.sleep(1)
                continue
            last_event_id = events[-1]['id']
            events = [e for e in events if e['type'] == memo.split(":")[0].lower()]
            completed += len(events)
            pbar.update(len(events))
            time.sleep(1)
        pbar.close()

        t2 = time.time()
        end_block_height = self.thorchain_client.get_block_height()
        total_time = t2 - t1
        total_blocks = end_block_height - start_block_height
        logging.info(f"<<< done. (Swaps: {completed} Blocks: {total_blocks}, {total_time} seconds)")


if __name__ == "__main__":
    main()
