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
    ):
        self.source_ip = source_ip
        self.source_port = source_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.window_size = window_size
        self.flags = flags
        self.payload = payload
        self.options = self.construct_options()

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

    def calculate_checksum(self) -> bytes:
        ip_pseudo = self.gen_ip_psuedo_header()
        header_with_zero_checksum = self.construct_header_with_checksum_val(0)
        return gen_checksum(
            ip_pseudo + header_with_zero_checksum + self.options + self.payload
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
        if self.flags & TCP_ACK == 0:
            ack_to_pack = 0
        result += struct.pack("!L", ack_to_pack)

        # Data Offset, Reserved, Flags
        data_offset = self.header_length() << 12
        do_r_f = data_offset + self.flags
        result += struct.pack("!H", do_r_f)

        # Window
        result += struct.pack("!H", self.window_size)

        # Checksum
        result += struct.pack("!H", checksum_val)

        # Urgent pointer
        result += struct.pack("!H", 0)

        # assert len(result) == self.header_length()*4
        return result

    def header_length(self) -> int:
        options_len = len(self.options)
        return options_len + TCP_HEADER_LEN_WO_OPTIONS

    def length(self) -> int:
        return len(self.payload) + self.header_length()

    def construct_options(self) -> bytes:
        return b""

    def construct_packet(self) -> bytes:
        return self.construct_header() + self.payload
