from logger import logger
import socket
from ipaddress import IPv4Address
from tcp import TCP, TCP_SYN
from ip import IPv4


def get_ephemeral_port() -> int:
    # NOTE: this socket is only used to obtain an ephemeral port number
    sock = socket.socket(socket.AF_INET)
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("", 0))
    _, port = sock.getsockname()
    sock.close()
    return port


class TCPSession:
    def __init__(self, dest_ip: str, dest_port: int):
        self.send_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
        )
        self.receive_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
        )

        self.source_ip = socket.gethostbyname(socket.gethostname())
        self.dest_ip = dest_ip

        self.dest_port = dest_port

        self.source_seq_num = 0
        self.source_ack_num = 0
        self.window_size = 64240

        self.source_port = get_ephemeral_port()

        self.setup_receiver()
        self.setup_sender()

    # Bind the receive socket
    def setup_receiver(self) -> int:
        pass

    # Bind the send socket
    def setup_sender(self) -> int:
        self.send_socket.bind((self.source_ip, self.source_port))
        self.send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def send_tcp(self, flags: int, payload: bytes):
        tcp_pkt = TCP(
            IPv4Address(self.source_ip),
            IPv4Address(self.dest_ip),
            self.source_port,
            self.dest_port,
            self.source_seq_num,
            self.source_ack_num,
            self.window_size,
            flags,
            payload,
        )
        ip_pkt = IPv4(
            IPv4Address(self.source_ip),
            IPv4Address(self.dest_ip),
            tcp_pkt.construct_packet(),
        )
        self.send_socket.sendto(ip_pkt.construct_packet(), (self.dest_ip, 1))
        logger.debug("sent TCP packet")

    def do_handshake(self):
        self.send_tcp(TCP_SYN, b"")
