# Takes in a packet as a byte string starting at the IP Header
# and returns the associated IPv4 object
# Returns NULL if the checksum of created packet does not match the original checksum
import struct

from ip import IPv4
from tcp import TCP
from httppacket import HTTP
from logger import logger

# Takes in a packet as a byte string starting at the IP Header
# and returns the associated IPv4 object
# Returns NULL if the checksum of created packet does not match the original checksum
def construct_IPobj_from_bytes(packet: bytes) -> IPv4:
    IPstructString = "!BBHHHBBHLL"
    IPHeader_unpacked = struct.unpack(IPstructString, packet[:20])
    IHL = IPHeader_unpacked[0]&0xf
    DSCP_ECN = IPHeader_unpacked[1]
    packet_id = IPHeader_unpacked[3]
    offset = IPHeader_unpacked[4]&((1 << 13) - 1)
    flags = (IPHeader_unpacked[4] >> 13)&((1 << 3) - 1)
    ttl = IPHeader_unpacked[5]
    source_ip = IPHeader_unpacked[8]
    dest_ip = IPHeader_unpacked[9]
    payload = packet[4 * IHL :]
    checksum = IPHeader_unpacked[7]
    
    options = b""
    if IHL > 5:
        options = packet[20:4*IHL]
    
    ret = IPv4(source_ip, dest_ip, payload, packet_id=packet_id, ttl=ttl, IHL=IHL, options=options, flags=flags, DSCP_ECN=DSCP_ECN)
    assert(ret.length == IPHeader_unpacked[2])


    if not ret.calculate_checksum() == checksum:
        logger.debug("Our IP checksum: " + str(ret.calculate_checksum()) + " Their IP checksum: " + str(checksum))
        logger.debug(IPHeader_unpacked[1])
        return None
    
    return ret


# Takes in a packet as a byte string starting at the TCP Header
# and returns the associated TCP object
# Returns NULL if the checksum of created packet does not match the original checksum
def construct_TCPobj_from_bytes(src_ip, dst_ip, packet: bytes) -> TCP:
    TCPstructString = "!HHLLHHHH"
    TCPHeader_unpacked = struct.unpack(TCPstructString, packet[:20])
    source_port = TCPHeader_unpacked[0]
    dest_port = TCPHeader_unpacked[1]
    seq_num = TCPHeader_unpacked[2]
    ack_num = TCPHeader_unpacked[3]

    offset_and_flags = TCPHeader_unpacked[4]
    offset = (offset_and_flags >> 12)
    flags = offset_and_flags - (offset << 12)
    
    window_size = TCPHeader_unpacked[5]
    checksum = TCPHeader_unpacked[6]
    payload = packet[4 * offset :]
    options = b""
    if offset > 5:
        options = packet[20:4*offset]
        logger.debug("saw packed with big offset " + str(offset) + " with options " + str(options))
    ret = TCP(
        src_ip, dst_ip, source_port, dest_port, seq_num, ack_num, window_size, flags, payload, offset=offset, options=options
    )
    calculated_checksum = ret.calculate_checksum()
    if checksum != calculated_checksum:
        logger.debug(f"Threw away packet due to bad checksum, us: {calculated_checksum}, them: {checksum}")
        return None
    logger.debug("Our TCP checksum " + str(ret.calculate_checksum()) + " Their TCP checksum: " + str(checksum))
    return ret

# Takes in a packet as a byte string starting at the HTTP Header
# and returns the associated HTTP object
def constructHTTPobj_from_bytes(packet: bytes) -> HTTP:
    return HTTP("wherever.com", 80, "/some/path")
