import struct
from logger import logger
import socket
from ipaddress import IPv4Address
from reconstruct import construct_IPobj_from_bytes, construct_TCPobj_from_bytes
from tcp import TCP, TCP_SYN, TCP_ACK
from ip import IPv4
from httppacket import HTTP


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

        self.source_seq_num = 83487
        self.source_ack_num = 0
        self.window_size = 64240

        self.source_port = get_ephemeral_port()
        logger.debug(f"MY PORT: {self.source_port}")

        self.setup_receiver()
        self.setup_sender()

    # Bind the receive socket
    def setup_receiver(self) -> int:
        self.receive_socket.bind((self.source_ip, 0))

    # Bind the send socket
    def setup_sender(self) -> int:
        self.send_socket.bind((self.source_ip, self.source_port))
        self.send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def send_tcp(self, flags: int, payload: bytes = b""):
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
        self.source_seq_num += len(payload)

    def recv_tcp(self, first_recv=False) -> TCP:
        # TODO: potentially timeout for a retry
        ip_pkt = None
        tcp_pkt = None
        while 1:
            try:
                rcvd_bytes = self.receive_socket.recv(65535)
                ip_pkt = construct_IPobj_from_bytes(rcvd_bytes)
                if int(ip_pkt.source_ip) != int(IPv4Address(self.dest_ip)):
                    continue
                logger.debug(
                    f"Saw packet {IPv4Address(ip_pkt.source_ip)} -> {IPv4Address(ip_pkt.dest_ip)}"
                )
                tcp_pkt = construct_TCPobj_from_bytes(ip_pkt.payload)
                logger.debug(
                    f"Saw packet {IPv4Address(ip_pkt.source_ip)}:{tcp_pkt.source_port} -> {IPv4Address(ip_pkt.dest_ip)}:{tcp_pkt.dest_port}"
                )
                if tcp_pkt.dest_port != self.source_port:
                    continue
                if first_recv:
                    self.source_ack_num = tcp_pkt.seq_num
                expected_seq_num = self.source_ack_num + len(tcp_pkt.payload)
                if tcp_pkt.seq_num != expected_seq_num:
                    logger.info(
                        f"Got a packet from the future. SEQ: {tcp_pkt.seq_num}, EXPECTED: {expected_seq_num}"
                    )
                    # send another ACK for what we know about
                    self.send_tcp(TCP_ACK)
                    continue
                break
            except struct.error as e:
                continue
            except Exception as e:
                continue
        logger.debug("Got a packet destined for me!")
        self.source_ack_num = tcp_pkt.seq_num + len(tcp_pkt.payload) + 1
        return tcp_pkt

    def do_handshake(self):
        self.send_tcp(TCP_SYN)
        syn_ack = self.recv_tcp(True)
        self.send_tcp(TCP_ACK)

    def do_get_request(self, netloc: str, path: str):
        # Build get request
        get_request = HTTP(netloc, path).construct_packet()
        self.send_tcp(TCP_ACK, get_request)
