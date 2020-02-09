
class Coin:
    def __init__(self, asset, amount):
        self.asset = asset
        self.amount = amount

    def __repr__(self):
        return "<Coin %d%s>" % (self.amount, self.asset)

    def __str__(self):
        return "%d%s" % (self.amount, self.asset)
