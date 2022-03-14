#!/usr/bin/env python3

import struct
import unittest
from ipaddress import IPv4Address
import socket

# IP HEADER CONSTANTS
IP_VERSION = 4
IP_HDR_LEN_WORDS = 5
IP_HDR_LEN_BYTES = 20
TCP_PROTOCOL = 6
CHECKSUM_OFFSET = 79


#TCP Flags
TCP_FIN = 1
TCP_SYN = 2
TCP_RST = 4
TCP_PSH = 8
TCP_ACK = 16
TCP_URG = 32
TCP_ECE = 64
TCP_CWR = 128
TCP_NS  = 256

TCP_HEADER_LEN_WO_OPTIONS = 5

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

class HTTP:

  def __init__(self):
    pass
  
  def length(self) -> int:
    return 0

  def construct_packet(self) -> bytes:
    return b"This is where the HTTP stuff goes"

class TCP:

  def __init__(self, source_port: int, dest_port: int, seq_num: int, ack_num: int, window_size: int, flags: int, payload: HTTP):
    self.source_port = source_port
    self.dest_port = dest_port
    self.seq_num = seq_num
    self.ack_num = ack_num
    self.window_size = window_size
    self.flags = flags
    self.payload = payload
    self.options = self.construct_options()

  def construct_header(self, checksum = None) -> bytes:
    result = b""
    
    # Source Port
    result += struct.pack("!H", self.source_port)

    # Destination Port
    result += struct.pack("!H", self.dest_port)

    # Sequence Number
    result += struct.pack("!L", self.seq_num)

    # Ack Number
    result += struct.pack("!L", self.ack_num)

    # Data Offset, Reserved, Flags
    data_offset = self.header_length() << 12
    do_r_f = data_offset + self.flags
    result += struct.pack("!H", do_r_f)

    # Window
    result += struct.pack("!H", self.window_size)

    # Checksum
    result += struct.pack("!H", checksum or 0)

    # Urgent pointer
    result += struct.pack("!H", 0)

    if not checksum:
      cs = gen_checksum(result)
      return self.construct_header(checksum=cs)

    # assert len(result) == self.header_length()*4
    return result

  def header_length(self) -> int:
    options_len = len(self.options)
    return options_len + TCP_HEADER_LEN_WO_OPTIONS
    

  def length(self) -> int:
    return self.payload.length() + self.header_length()

  def construct_options(self) -> bytes:
    return b""

  def construct_packet(self) -> bytes:
    return self.construct_header() + self.payload.construct_packet()



class IPv4:
  def __init__(self, source_ip: IPv4Address, dest_ip: IPv4Address, payload: TCP):
    self.payload = payload
    self.length: int = IP_HDR_LEN_BYTES + payload.length()
    self.source_ip = source_ip
    self.dest_ip = dest_ip
    self.ttl: int = 255

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
  http_pkt = HTTP()
  tcp_pkt = TCP(35898, 22, 1, 1, 1, TCP_SYN+TCP_ACK, http_pkt)
  ip_pkt = IPv4(src_ip, dst_ip, tcp_pkt)
  # print(ip_pkt.construct_header().hex())
  print(ip_pkt.construct_packet().hex())
  
  receive_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
  receive_socket.bind(("0.0.0.0", 0))
  receive_socket.recv(1000)
  
  send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

if __name__ == "__main__":
  main()
