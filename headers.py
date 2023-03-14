# importing the required libraries
import socket
from struct import *
from util import checksum


'''
    Function: generates IP header
    Parameters: 
        id: packet ID
        s_ip: source ip
        d_ip: destination ip
    Returns: ip header
'''
def generate_header_ip(packet_id, src_ip, dst_ip):
    return pack('!BBHHHBBH4s4s', (4 << 4) + 5, 0, 0, packet_id, 0, 255, socket.IPPROTO_TCP, 0, socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip))

'''
    Function: generates TCP header without checksum
    Parameters: 
        port: source port
        order: order num
        ack_num: ack num
        fin: flag
        syn: flag
        rst: flag
        psh: flag
        ack: flag
    Returns: tcp header
'''
def generate_header_tcp_no_checksum(port, order, ack_num, fin, syn, rst, psh, ack):
    flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (0 << 5)
    tcp_header = pack('!HHLLBBHHH', port, 80, order, ack_num, 5 << 4, flags, socket.htons(5840), 0, 0)
    return tcp_header

'''
    Function: generates TCP header with checksum
    Parameters: 
        port: source port
        order: order num
        ack_num: ack num
        fin: flag
        syn: flag
        rst: flag
        psh: flag
        ack: flag
        s_ip: source ip
        d_ip: destination ip
        payload: data to calculate checksum
    Returns: tcp header
'''
def generate_header_tcp_checksum(header_t, port, order, ack_num, fin, syn, rst, psh, ack, s_ip, d_ip, payload):
    flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (0 << 5)
    packet_maker = pack('!4s4sBBH', socket.inet_aton(s_ip), socket.inet_aton(d_ip), 0, socket.IPPROTO_TCP,
                        len(header_t) + len(payload))
    packet_maker = packet_maker + header_t + bytes(payload, 'utf-8')
    header_t = pack('!HHLLBBH', port, 80, order, ack_num, 5 << 4, flags,
                    socket.htons(5840)) + pack('H', checksum(packet_maker)) + pack('!H', 0)
    return header_t