
from coin import Coin
 
class Account:
    def __init__(self, address):
        self.address = address
        self.balances = []

    def sub(self, coins):
        if not isinstance(coins, list):
            coins = [coins]

        for coin in coins:
            for i, c in enumerate(self.balances):
                if coin.asset == c.asset:
                    self.balances[i].amount -= coin.amount
                    if self.balances[i].amount < 0:
                        print("Balance:", self.address, self.balances[i])
                        self.balances[i].amount = 0
                        #raise Exception("insufficient funds")

    def add(self, coins):
        if not isinstance(coins, list):
            coins = [coins]

        for coin in coins:
            found = False
            for i, c in enumerate(self.balances):
                if coin.asset == c.asset:
                    self.balances[i].amount += coin.amount
                    found = True
                    break
            if not found:
                self.balances.append(coin)

    def get(self, asset):
        for coin in self.balances:
            if asset == coin.asset:
                return coin.amount

        return 0


class Binance:
    chain = "Binance"

    def __init__(self):
        self.accounts = {}

    def _calculateGas(self, coins):
        if not isinstance(coins, list) or len(coins) == 1:
            return Coin("BNB", 37500)
        return Coin("BNB", 30000 * len(coins))

    def get_account(self, addr):
        if addr in self.accounts:
            return self.accounts[addr] 
        return Account(addr)

    def set_account(self, acct):
        self.accounts[acct.address] = acct

    def seed(self, addr, coins):
        acct = self.get_account(addr)
        acct.add(coins)
        self.accounts[addr] = acct

    def transfer(self, txn):
        """
        Makes a transfer on the binance chain. Returns gas used
        """
        if txn.chain != Binance.chain:
            raise Exception('Cannot transfer. {} is not {}'.format(Binance.chain, txn.chain))

        from_acct = self.get_account(txn.fromAddress)
        to_acct = self.get_account(txn.toAddress)

        gas = self._calculateGas(txn.coins)
        from_acct.sub(gas)

        from_acct.sub(txn.coins)
        to_acct.add(txn.coins)

        self.set_account(from_acct)
        self.set_account(to_acct)

        gas.asset = "BNB.BNB"
        return gas
