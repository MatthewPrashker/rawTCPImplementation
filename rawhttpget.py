#!/usr/bin/env python3

import struct
import unittest
from ipaddress import IPv4Address

# IP HEADER CONSTANTS
IP_VERSION = 4
IP_HDR_LEN_WORDS = 5
IP_HDR_LEN_BYTES = 20
TCP_PROTOCOL = 6
CHECKSUM_OFFSET = 79

# Takes in a string of bytes and computes the cumulative checksum of these bytes
def gen_checksum(data: bytes) -> int:
  cs = 0
  for i in range(0, len(data), 2):
    cs += (data[i] << 8) + data[i + 1]
  cs = (cs & 0xffff) + (cs >> 16)
  return (~cs) & 0xffff

class TestChecksum(unittest.TestCase):
  examples = [
    {
      "header": "45200b84551f400024060000cc2cc03c0a030021",
      "sum": 0x5fa8,
    },
    {
      "header": "4500003465024000400600000a030021cc2cc03c",
      "sum": 0x3f35,
    },
  ]

  def test_checksum(self):
    for example in self.examples:
      self.assertEqual(gen_checksum(bytes.fromhex(example['header'])), example['sum'])

class TCP:
  def construct_header(self) -> bytes:
    return b""

  def length(self) -> int:
    return 0

  def construct_packet(self) -> bytes:
    return b""

class IPv4:
  def __init__(self, source_ip: IPv4Address, dest_ip: IPv4Address, payload: TCP):
    self.payload: TCP = payload
    self.length: int = IP_HDR_LEN_BYTES + payload.length()
    self.source_ip: IPv4Address = source_ip
    self.dest_ip: IPv4Address = dest_ip
    self.ttl: chr = 255

  def construct_header(self, checksum = None) -> bytes:
    result = b""

    # Version and IHL
    ver_and_len = (IP_VERSION << 4) + IP_HDR_LEN_WORDS
    result += struct.pack("!B", ver_and_len)

    # Service Type
    result += struct.pack("!B", 0)

    # Total Length
    result += struct.pack("!H", self.length)

    # Identification
    result += struct.pack("!H", 0)

    # Flags & Offset
    #   just set don't fragment
    #   0 for offset
    flags = 2 << 13
    result += struct.pack("!H", flags)

    # Time to Live
    result += struct.pack("!B", 255)

    # Protocol
    result += struct.pack("!B", TCP_PROTOCOL)

    # Add checksum
    result += struct.pack("!H", checksum or 0)

    # Source IP
    result += struct.pack("!L", int(self.source_ip))

    # Dest IP
    result += struct.pack("!L", int(self.dest_ip))

    if not checksum:
      cs = gen_checksum(result)
      return self.construct_header(checksum=cs)

    return result

  def construct_packet(self) -> bytes:
    return self.construct_header() + self.payload.construct_packet()

def main():
  src_ip = IPv4Address("10.3.0.33")
  dst_ip = IPv4Address("10.3.0.1")
  tcp_pkt = TCP()
  ip_pkt = IPv4(src_ip, dst_ip, tcp_pkt)
  print(ip_pkt.construct_header().hex())

if __name__ == "__main__":
  main()
