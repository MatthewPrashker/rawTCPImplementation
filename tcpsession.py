import struct
from logger import logger
import socket
from ipaddress import IPv4Address
from reconstruct import construct_IPobj_from_bytes, construct_TCPobj_from_bytes
from tcp import TCP, TCP_SYN, TCP_ACK, TCP_PSH, TCP_FIN
from ip import IPv4
from httppacket import HTTP
from typing import List


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

        self.pkts_received: List[TCP] = []

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
        logger.debug("Length of TCP packet " + str(len(ip_pkt.construct_packet())))
        logger.debug(ip_pkt.length)
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
                    self.source_ack_num = tcp_pkt.seq_num + 1
                break
            # Not an IP or TCP packet
            except struct.error as e:
                continue
            except Exception as e:
                continue
        logger.debug("Got a packet destined for me!")
        logger.debug(str(ip_pkt.length))
        self.handle_recvd_packet(tcp_pkt, first_recv)
        return tcp_pkt

    def handle_recvd_packet(self, incoming_pkt: TCP, first_recv: bool):
        should_ack = first_recv or len(incoming_pkt.payload) != 0
        # Ignore duplicate packets
        for pkt_already_have in self.pkts_received:
            if pkt_already_have.seq_num == incoming_pkt.seq_num:
                if should_ack:
                    self.send_tcp(TCP_ACK)
                return
        self.sort_pkts_received()
        if len(incoming_pkt.payload) > 0:
            self.pkts_received.append(incoming_pkt)
        latest_packet_without_break = self.latest_packet_without_break()
        if latest_packet_without_break:
            self.source_ack_num = (
                latest_packet_without_break.seq_num
                + len(latest_packet_without_break.payload)
                + 1
            )

        if should_ack:
            self.send_tcp(TCP_ACK)

    def latest_packet_without_break(self) -> TCP:
        if len(self.pkts_received) == 0:
            return None
        last_pkt = self.pkts_received[0]
        for pkt in self.pkts_received[1:]:
            exp_next_seq = last_pkt.seq_num + len(last_pkt.payload)
            if pkt.seq_num == exp_next_seq:
                last_pkt = pkt
                continue
            else:
                break

        return last_pkt

    def sort_pkts_received(self):
        self.pkts_received = sorted(self.pkts_received, key=lambda pkt: pkt.seq_num)

    def build_payload_stream(self):
        ret = b""
        self.sort_pkts_received()
        for pkt in self.pkts_received:
            ret += pkt.payload
        return ret

    def do_handshake(self):
        self.send_tcp(TCP_SYN)
        self.source_seq_num += 1
        syn_ack = self.recv_tcp(True)
        # gets acked in recv_tcp

    def do_get_request(self, netloc: str, path: str) -> bytes:
        # Build get request
        get_request = HTTP(netloc, path).construct_packet()
        self.send_tcp(TCP_ACK + TCP_PSH, get_request)
        while True:
            curr_pkt = self.recv_tcp()
            if curr_pkt.flag_set(TCP_FIN):
                break
        return self.build_payload_stream()


import unittest


class TestACKS(unittest.TestCase):
    def make_ex_tcp(seq: int) -> TCP:
        return TCP(0, 0, 0, 0, seq, 0, 0, 0, b"a")

    def test_sort(self):
        example = TCPSession("1.1.1.1", 80)
        example.pkts_received = [
            TestACKS.make_ex_tcp(3),
            TestACKS.make_ex_tcp(2),
            TestACKS.make_ex_tcp(1),
            TestACKS.make_ex_tcp(4),
        ]
        example.sort_pkts_received()
        for i in range(0, 4):
            self.assertEqual(example.pkts_received[i].seq_num, i + 1)

    def test_acks(self):
        example = TCPSession("1.1.1.1", 80)
        example.pkts_received = [
            TestACKS.make_ex_tcp(1),
            TestACKS.make_ex_tcp(3),
            TestACKS.make_ex_tcp(5),
            TestACKS.make_ex_tcp(4),
            TestACKS.make_ex_tcp(5),
            TestACKS.make_ex_tcp(7),
            TestACKS.make_ex_tcp(8),
            TestACKS.make_ex_tcp(9),
            TestACKS.make_ex_tcp(10),
        ]
        self.assertEqual(example.latest_packet_without_break().seq_num, 5)
        example.handle_recvd_packet(TestACKS.make_ex_tcp(6))
        self.assertEqual(example.latest_packet_without_break().seq_num, 10)
