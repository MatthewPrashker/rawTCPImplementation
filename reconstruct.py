# Takes in a packet as a byte string starting at the IP Header
# and returns the associated IPv4 object
# Returns NULL if the checksum of created packet does not match the original checksum
import struct

from ip import IPv4
from tcp import TCP
from http import HTTP


def construct_IPobj_from_bytes(packet: bytes) -> IPv4:
    IPstructString = "!BBHHHBBHLL"
    IPHeader_unpacked = struct.unpack(IPstructString, packet)
    source_ip = IPHeader_unpacked[8]
    dest_ip = IPHeader_unpacked[9]

    header_length_words = max(5, IPHeader_unpacked[0] & (1 << 4 - 1))
    payload = construct_TCPobj_from_bytes(packet[4 * header_length_words :])

    checksum = IPHeader_unpacked[7]
    ret = IPv4(source_ip, dest_ip, payload)
    if ret.get_checksum() == checksum:
        return ret
    return None


# Takes in a packet as a byte string starting at the TCP Header
# and returns the associated TCP object
# Returns NULL if the checksum of created packet does not match the original checksum
def construct_TCPobj_from_bytes(packet: bytes) -> TCP:
    TCPstructString = "!HHLLHHHH"
    TCPHeader_unpacked = struct.unpack(TCPstructString, packet)
    source_port = TCPHeader_unpacked[0]
    dest_port = TCPHeader_unpacked[1]
    seq_num = TCPHeader_unpacked[2]
    ack_num = TCPHeader_unpacked[3]

    offset_and_flags = TCPHeader_unpacked[4]
    offset = (offset_and_flags >> 12) & ((1 << 4) - 1)
    flags = offset_and_flags & ((1 << 9) - 1)

    window_size = TCPHeader_unpacked[5]
    payload = constructHTTPobj_from_bytes(packet[4 * offset :])

    ret = TCP(source_port, dest_port, seq_num, ack_num, window_size, flags, payload)

    # Verify checksum
    check_sum = TCPHeader_unpacked[6]
    if check_sum == ret.get_checksum():
        return ret

    return None  # Check sum failed


# Takes in a packet as a byte string starting at the HTTP Header
# and returns the associated HTTP object
def constructHTTPobj_from_bytes(packet: bytes) -> HTTP:
    return HTTP()
