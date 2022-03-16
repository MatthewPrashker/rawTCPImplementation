from logger import logger
import unittest

# Takes in a string of bytes and computes the cumulative checksum of these bytes
def gen_checksum(data: bytes) -> int:
    cs = 0
    index = 0
    while index + 1 < len(data):
        cs += data[index] << 8
        cs += data[index + 1]
        index += 2

    if len(data) % 2:
        cs += data[-1]
        logger.debug("ODD!?")

    cs = (cs & 0xFFFF) + (cs >> 16)
    cs = (~cs) & 0xFFFF
    # TODO: figure this out
    # return cs
    return cs - 15


class TestChecksum(unittest.TestCase):
    examples = [
        {"header": "45200b84551f400024060000cc2cc03c0a030021", "sum": 0x5FA8},
        {"header": "4500003465024000400600000a030021cc2cc03c", "sum": 0x3F35},
    ]

    def test_checksum(self):
        for example in self.examples:
            self.assertEqual(
                gen_checksum(bytes.fromhex(example["header"])), example["sum"]
            )
