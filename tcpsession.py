import struct
from logger import logger
import socket
from ipaddress import IPv4Address
from reconstruct import construct_IPobj_from_bytes, construct_TCPobj_from_bytes
from tcp import TCP, TCP_SYN, TCP_ACK, TCP_PSH, TCP_FIN
from ip import IPv4
from httppacket import HTTP
from typing import List

MAX_SEQ_NUM = (1 << 32)


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
        self.starting_seq_num: int = 0
        
        self.in_slow_start = True
        self.unacked_bytes = 0
        self.cwnd = 4000
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
                tcp_pkt = construct_TCPobj_from_bytes(ip_pkt.source_ip, ip_pkt.dest_ip, ip_pkt.payload)
                
                if tcp_pkt.flag_set(TCP_FIN):
                    logger.debug("got FIN")

                logger.debug(
                    f"Saw packet {IPv4Address(ip_pkt.source_ip)}:{tcp_pkt.source_port} -> {IPv4Address(ip_pkt.dest_ip)}:{tcp_pkt.dest_port}"
                )
                if tcp_pkt and tcp_pkt.dest_port != self.source_port:
                    continue
                if not tcp_pkt:
                    self.send_tcp(TCP_ACK)
                    continue
                if first_recv:
                    self.source_ack_num = tcp_pkt.seq_num + 1
                break
            # Not an IP or TCP packet
            except struct.error as e:
                logger.warn("struct unpack error: "+str(e))
                continue
            except Exception as e:
                logger.debug("here")
                continue
        logger.debug("Got a packet destined for me!")
        logger.debug(str(ip_pkt.length))
        self.handle_recvd_packet(tcp_pkt, first_recv)
        #self.show_seq_numbers()
        return tcp_pkt

    def handle_recvd_packet(self, incoming_pkt: TCP, first_recv: bool):
        if first_recv:
            self.starting_seq_num = (incoming_pkt.seq_num + 1)%MAX_SEQ_NUM
        should_ack = first_recv or len(incoming_pkt.payload) != 0
        # Ignore duplicate packets
        for pkt_already_have in self.pkts_received:
            if pkt_already_have.seq_num == incoming_pkt.seq_num:
                if should_ack:
                    self.send_tcp(TCP_ACK)
                return
        
        if len(incoming_pkt.payload) > 0:
            
            #Packet looped around to beginning
            if((incoming_pkt.seq_num + len(incoming_pkt.payload))%MAX_SEQ_NUM < self.starting_seq_num):
                incoming_pkt.fake_seq_num += MAX_SEQ_NUM
            
            self.pkts_received.append(incoming_pkt)
        self.sort_pkts_received()

        if not first_recv:
            self.source_ack_num = self.max_endpoint()

        logger.debug("Seq num received: " + str(incoming_pkt.seq_num-self.starting_seq_num) + " Seq num expected: " + str(self.source_ack_num-self.starting_seq_num))
        if should_ack:
            self.send_tcp(TCP_ACK)
    
    def show_seq_numbers(self):
      self.sort_pkts_received()
      for pkt in self.pkts_received:
        print(str(pkt.seq_num) + "  " + str(len(pkt.payload)))


    # TODO: remove me
    def latest_packet_without_break(self) -> TCP:
        if len(self.pkts_received) == 0:
            return None
    
        last_pkt = self.pkts_received[0]
        for pkt in self.pkts_received[1:]:
            exp_next_seq = last_pkt.fake_seq_num + len(last_pkt.payload)
            if pkt.seq_num == exp_next_seq:
                last_pkt = pkt
                continue
            else:
                break

        return last_pkt
    
    def max_endpoint(self) -> int:
      self.sort_pkts_received()
      ret = self.starting_seq_num
      logger.debug([("len:"+str(len(x.payload)), "seq:"+str(x.seq_num - self.starting_seq_num)) for x in self.pkts_received])
      for pkt in self.pkts_received:
        curr_endpoint = (pkt.fake_seq_num + len(pkt.payload))
        if(pkt.seq_num > ret):
          return ret
        ret = curr_endpoint
      return ret

    def sort_pkts_received(self):
        self.pkts_received = sorted(self.pkts_received, key=lambda pkt: pkt.fake_seq_num)

      

    def build_payload_stream(self):
        self.sort_pkts_received()
        start = self.pkts_received[0].seq_num
        end = self.pkts_received[-1].fake_seq_num + len(self.pkts_received[-1].payload)
        for pkt in self.pkts_received:
            ending = pkt.fake_seq_num + len(pkt.payload)
            if ending > end:
                end = ending
        final_len = end - start
        ret = [b""]*final_len
        #i = 0
        for pkt in self.pkts_received:
            cur_rel_seq = pkt.fake_seq_num - start 
            for i in range(len(pkt.payload)):
                if ret[cur_rel_seq + i] == b"":
                    ret[cur_rel_seq + i] = pkt.payload[i:i+1]
            
        return b"".join(ret)

    def do_handshake(self):
        self.send_tcp(TCP_SYN)
        self.source_seq_num = (1 + self.source_seq_num)%MAX_SEQ_NUM
        syn_ack = self.recv_tcp(True)
        logger.debug("First seq num: " + str(self.starting_seq_num))
        # gets acked in recv_tcp

    
    def do_teardown(self):
      self.send_tcp(TCP_FIN + TCP_ACK)
      self.send_socket.close()
      self.receive_socket.close()

    def do_get_request(self, netloc: str, path: str) -> bytes:
        # Build get request
        get_request = HTTP(netloc, path).construct_packet()
        self.send_tcp(TCP_ACK + TCP_PSH, get_request)
        final_endpoint = -1
        while True:
            curr_pkt = self.recv_tcp()

            if curr_pkt.flag_set(TCP_FIN):
                if final_endpoint == -1:
                    final_endpoint = (curr_pkt.seq_num + len(curr_pkt.payload))%MAX_SEQ_NUM
                    logger.debug(f"FINAL SEQ: {final_endpoint-self.starting_seq_num}")
                
            if(self.max_endpoint() == final_endpoint):
              break
        self.do_teardown()
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
