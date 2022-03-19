import struct
from checksum import gen_checksum
from ipaddress import IPv4Address

# IP HEADER CONSTANTS
IP_VERSION = 4
TCP_PROTOCOL = 6

class IPv4:
    def __init__(self, source_ip: IPv4Address, dest_ip: IPv4Address, payload: bytes, packet_id : int = 0, ttl : int = 255, IHL=5, options=b"", flags:int = 2, DSCP_ECN=0):
        self.payload = payload
        self.length: int = 4*IHL + len(payload)
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.ttl: int = ttl
        self.checksum = -1
        self.packet_id = packet_id
        self.IHL = IHL
        self.options = options
        self.flags = flags
        self.DSCP_ECN = DSCP_ECN

    def construct_header(self, checksum=-1) -> bytes:
        result = b""

        # Version and IHL
        ver_and_len = (IP_VERSION << 4) + self.IHL
        result += struct.pack("!B", ver_and_len)

        # Service Type
        result += struct.pack("!B", self.DSCP_ECN)

        # Total Length
        result += struct.pack("!H", self.length)

        # Identification
        result += struct.pack("!H", self.packet_id)

        # Flags & Offset
        #   just set don't fragment
        #   0 for offset
        result += struct.pack("!H", (self.flags) << 13)

        # Time to Live
        result += struct.pack("!B", self.ttl)

        # Protocol
        result += struct.pack("!B", TCP_PROTOCOL)

        # Add checksum
        if checksum == -1:
            result += struct.pack("!H", 0)
        else:
            result += struct.pack("!H", checksum)

        # Source IP
        result += struct.pack("!L", int(self.source_ip))

        # Dest IP
        result += struct.pack("!L", int(self.dest_ip))
        
        if self.IHL > 5:
            result += struct.pack("!" + (self.IHL - 5)*"B", self.options)

        if checksum == -1:
            cs = gen_checksum(result)
            self.checksum = cs
            return self.construct_header(checksum=cs)

        return result

    def calculate_checksum(self) -> int:
        if self.checksum == -1:
            self.construct_header()
        return self.checksum
    
    def construct_packet(self) -> bytes:
        return self.construct_header() + self.payload
