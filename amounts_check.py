import argparse

from thorchain import ThorchainClient
from chains import MockBinance

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binance", default="http://localhost:26660", help="Mock binance server"
    )
    parser.add_argument(
        "--thorchain", default="http://localhost:1317", help="Thorchain API url"
    )

    args = parser.parse_args()

    calc(args.binance, args.thorchain)

def calc(bnb_addr, thorchain_addr):
    thorchain_client = ThorchainClient(thorchain_addr)
    binance = MockBinance(bnb_addr)

    vault_balances = {}
    total_bond = 0

    asgards = thorchain_client.get_asgards()
    for asgard in asgards:
        for coin in asgard['coins'] or []:
            if not coin['asset'] in vault_balances:
                vault_balances[coin['asset']] = 0
            vault_balances[coin['asset']] += int(coin['amount'])

    yggs = thorchain_client.get_yggdrasil()
    for ygg in yggs:
        for coin in ygg['vault']['coins']:
            if not coin['asset'] in vault_balances:
                vault_balances[coin['asset']] = 0
            vault_balances[coin['asset']] += int(coin['amount'])

    vault_data = thorchain_client.get_vault_data()
    total_reserve = int(vault_data['total_reserve'])

    node_accounts = thorchain_client.get_node_accounts()
    for na in node_accounts:
        total_bond += int(na['bond'])

    pools = thorchain_client.get_pools()
    if len(pools) == 0:
        print("no pools, exiting")
        return
    pool_rune = 0
    pool_address = pools[0]['pool_address']

    for pool in pools:
        pool_rune += int(pool['balance_rune'])
        if pool['asset'] in vault_balances:
            print(vault_balances[pool['asset']], "==", pool['balance_asset'])

    print(vault_balances['BNB.RUNE-A1F'], "==", total_reserve + total_bond + pool_rune)

if __name__ == "__main__":
    main()
