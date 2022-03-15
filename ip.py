import struct
from checksum import gen_checksum
from ipaddress import IPv4Address
from tcp import TCP

# IP HEADER CONSTANTS
IP_VERSION = 4
IP_HDR_LEN_WORDS = 5
IP_HDR_LEN_BYTES = 20
TCP_PROTOCOL = 6
CHECKSUM_OFFSET = 79


class IPv4:
    def __init__(self, source_ip: IPv4Address, dest_ip: IPv4Address, payload: bytes):
        self.payload = payload
        self.length: int = IP_HDR_LEN_BYTES + len(payload)
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.ttl: int = 255

    def construct_header(self, checksum=None) -> bytes:
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
        return self.construct_header() + self.payload
