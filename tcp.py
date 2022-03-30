import struct
from checksum import gen_checksum
from ipaddress import IPv4Address

# TCP Flags
TCP_FIN = 1
TCP_SYN = 2
TCP_RST = 4
TCP_PSH = 8
TCP_ACK = 16
TCP_URG = 32
TCP_ECE = 64
TCP_CWR = 128
TCP_NS = 256

# TCP Constants
TCP_HEADER_LEN_WO_OPTIONS = 5
TCP_PROTOCOL = 6


class TCP:
    def __init__(
        self,
        source_ip: IPv4Address,
        dest_ip: IPv4Address,
        source_port: int,
        dest_port: int,
        seq_num: int,
        ack_num: int,
        window_size: int,
        flags: int,
        payload: bytes,
        offset: int = 5,
        options: bytes = b""
    ):
        self.source_ip = source_ip
        self.source_port = source_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.seq_num = seq_num
        self.fake_seq_num = seq_num
        self.ack_num = ack_num
        self.window_size = window_size
        self.flags = flags
        self.payload = payload
        self.offset = offset
        self.options = options

    def gen_ip_psuedo_header(self) -> bytes:
        result = b""

        # Source IP
        result += struct.pack("!L", int(self.source_ip))

        # Dest IP
        result += struct.pack("!L", int(self.dest_ip))

        # Zeros
        result += struct.pack("!B", 0)

        # Protocol
        result += struct.pack("!B", TCP_PROTOCOL)

        # Length
        result += struct.pack("!H", self.length())

        return result

    def calculate_checksum(self) -> int:
        ip_psuedo = self.gen_ip_psuedo_header()
        header_with_zero_checksum = self.construct_header_with_checksum_val(0)
        return gen_checksum(
            ip_psuedo + header_with_zero_checksum + self.payload
        )

    def construct_header(self) -> bytes:
        checksum = self.calculate_checksum()
        return self.construct_header_with_checksum_val(checksum)

    def construct_header_with_checksum_val(self, checksum_val: int) -> bytes:
        result = b""

        # Source Port
        result += struct.pack("!H", self.source_port)

        # Destination Port
        result += struct.pack("!H", self.dest_port)

        # Sequence Number
        result += struct.pack("!L", self.seq_num)

        # Ack Number
        ack_to_pack = self.ack_num
        if not self.flag_set(TCP_ACK):
            ack_to_pack = 0
        result += struct.pack("!L", ack_to_pack)

        # Data Offset, Reserved, Flags
        data_offset = self.offset << 12
        do_r_f = data_offset + self.flags
        result += struct.pack("!H", do_r_f)

        # Window
        result += struct.pack("!H", self.window_size)

        # Checksum
        result += struct.pack("!H", checksum_val)

        # Urgent pointer
        result += struct.pack("!H", 0)
        
        # Options
        if self.offset > 5:
            result += self.options

        assert len(result) == self.offset*4
        return result

    def flag_set(self, flag: int) -> bool:
        return self.flags & flag != 0

    def length(self) -> int:
        return len(self.payload) + (self.offset*4)

    def construct_packet(self) -> bytes:
        return self.construct_header() + self.payload
