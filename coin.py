
class Coin:
    def __init__(self, asset, amount):
        self.asset = asset
        self.amount = amount

    def is_rune(self):
        return self.asset.startswith("RUNE")

    def is_zero(self):
        return self.amount == 0

    def equals(self, coin):
        return self.asset == coin.asset and self.amount == coin.amount

    def __repr__(self):
        return "<Coin %d%s>" % ((self.amount), self.asset)

    def __str__(self):
        return "%d%s" % ((self.amount), self.asset)
