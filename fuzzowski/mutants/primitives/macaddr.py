from ..mutant import Mutant
from uuid import getnode

class MacAddr(Mutant):
    def __init__(self, value: bytes = None, name: str = None):
        """
        Primitive that contains static content.

        Args:
            value: The static value
            name:

        """

        if value == None:
            mac = getnode()
            value_str = ''.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))
            value = bytes.fromhex(value_str)

        # This is basically a non fuzzable mutant, nothing else to do here
        super().__init__(value, name, fuzzable=False)
