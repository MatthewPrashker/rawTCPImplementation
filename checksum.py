import unittest

# Takes in a string of bytes and computes the cumulative checksum of these bytes
def gen_checksum(data: bytes) -> int:
    cs = 0
    for i in range(0, len(data), 2):
        cs += (data[i] << 8) + data[i + 1]
    cs = (cs & 0xFFFF) + (cs >> 16)
    return (~cs) & 0xFFFF


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
