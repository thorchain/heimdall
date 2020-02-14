class PoolError(Exception):
    """Basic exception for errors raised by pools"""

    def __init__(self, pool, msg=None):
        if msg is None:
            # Set some default useful error message
            msg = "An error occured with pool [{}]".format(pool)
        super().__init__(msg)
        self.msg = msg
        self.pool = pool


class MidgardPoolError(PoolError):
    """Pool midgard error"""

    def __init__(self, pool, field, expected, obtained):
        msg = "Midgard Pool [{}] || {} ==> {} != {}".format(
            pool, field, expected, obtained
        )
        super().__init__(pool, msg=msg)
        self.msg = msg
        self.field = field
        self.expected = expected
        self.obtained = obtained
