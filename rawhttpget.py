#!/usr/bin/env python3
import os
import random
import socket
import sys
import argparse
import time
from struct import *
from urllib.parse import urlparse
from urllib.parse import urlsplit

from headers import generate_header_ip, generate_header_tcp_no_checksum, generate_header_tcp_checksum
from util import client_ip, write, parse_commandline_url, set_congestion_control

CWND = 1
AWND = socket.htons(5840)

'''
    Function: first step of handshake, creates and sends syn request
    Parameters: 
        send_sock: send socket
        s_ip : ip of source
        d_ip : ip of destination
        port : source port
    Returns: None
'''


def syn(sock, s_ip, d_ip, port):
    header_t = generate_header_tcp_no_checksum(port, 0, 0, 0, 1, 0, 0, 0)
    header_t = generate_header_tcp_checksum(header_t, port, 0, 0, 0, 1, 0, 0, 0, s_ip, d_ip, '')
    header_i = generate_header_ip(54321, s_ip, d_ip)
    sock.sendto(header_i + header_t, (d_ip, 0))
    global run
    run = time.time()


'''
    Function: second step of handshake, creates and sends ack request
    Parameters: 
        send_sock: send socket
        s_ip : ip of source
        d_ip : ip of destination
        port : source port
    Returns: None
'''


def ack(sock, port, s_ip, d_ip, header):
    header_i = generate_header_ip(54322, s_ip, d_ip)
    header_t = generate_header_tcp_no_checksum(port, header[3], header[2] + 1, 0, 0, 0, 0, 1)
    header_t = generate_header_tcp_checksum(header_t, port, header[3], header[2] + 1, 0, 0,
                                            0, 0, 1, s_ip, d_ip, '')

    sock.sendto(header_i + header_t, (d_ip, 0))


'''
    Function: third step of handshake, receives syn-ack and sends ack
    Parameters: 
        send_s: send socket
        sock_r: receiving socket
        buffer: buffer size
        s_ip : ip of source
        d_ip : ip of destination
        port : source port
    Returns: unpacked TCP header
'''


def syn_ack_and_ack(sock_s, sock_r, buffer, s_ip, d_ip, port):
    packet = sock_r.recvfrom(buffer)[0]
    header_i_unpacked = unpack('!BBHHHBBH4s4s', packet[0:20])
    header_length = header_i_unpacked[0] & 0xF
    address_destination = socket.inet_ntoa(header_i_unpacked[8])
    address_source = socket.inet_ntoa(header_i_unpacked[9])
    header_t = packet[header_length * 4:header_length * 4 + 20]
    header_t_unpacked = unpack('!HHLLBBHHH', header_t)
    if address_source == s_ip and address_destination == d_ip and header_t_unpacked[5] == 18 and port == \
            header_t_unpacked[1] \
            and ((run - time.time()) < 60):
        ack(sock_s, port, s_ip, d_ip, header_t_unpacked)

    else:
        syn(sock_s, s_ip, d_ip, port)

    return header_t_unpacked


'''
    Function: send a HTTP get request to retrieve the file
    Parameters: 
        send_s: send socket
        s_ip : ip of source
        d_ip : ip of destination
        port : source port
        header_t: tcp header
        url: url for file
        hostname: host where file is hosted
    Returns: None
'''


def send_get_request(sock_s, s_ip, d_ip, port, header_t, url, host):
    header_i = generate_header_ip(54323, s_ip, d_ip)
    request = 'GET ' + url + ' HTTP/1.0\r\nHOST: ' + host + '\r\n\r\n'
    if len(request) % 2 != 0:
        request = request + " "
    header_t_updated = generate_header_tcp_no_checksum(port, header_t[3], header_t[2] + 1, 0, 0, 0, 1, 1)
    header_t_updated = generate_header_tcp_checksum(header_t_updated, port, header_t[3], header_t[2] + 1, 0, 0, 0, 1, 1,
                                                    s_ip, d_ip, request)
    packet = header_i + header_t_updated + bytes(request, 'utf-8')
    sock_s.sendto(packet, (d_ip, 0))


'''
    Function: downloads file
    Parameters: 
        send_s: send socket
        send_r: receiving socket
        buffer: size of buffer
        s_ip : ip of source
        d_ip : ip of destination
        port : source port
        file_name: file name
    Returns: None
'''


def download(sock_s, sock_r, buffer, s_ip, d_ip, port, file_name):
    res = {}
    count = 0
    while True:
        print(count)
        packet = sock_r.recvfrom(buffer)[0]
        header_i_unpacked = unpack('!BBHHHBBH4s4s', packet[0:20])
        header_i_length = header_i_unpacked[0] & 0xF
        address_destination = socket.inet_ntoa(header_i_unpacked[8])
        address_source = socket.inet_ntoa(header_i_unpacked[9])
        header_t = packet[header_i_length * 4:header_i_length * 4 + 20]
        header_t_unpacked = unpack('!HHLLBBHHH', header_t)
        header_t_length = header_t_unpacked[4] >> 4

        h_size = header_i_length * 4 + header_t_length * 4
        content_size = len(packet) - h_size
        if header_t_unpacked[1] == port and address_destination == d_ip and address_source == s_ip and content_size > 0:
            count += 1
            content = packet[h_size:]
            res[header_t_unpacked[2]] = content
            header_i = generate_header_ip(54322, s_ip, d_ip)
            global AWND
            AWND = header_t_unpacked[6]
            global CWND
            CWND = set_congestion_control(CWND, AWND)
            header_t = generate_header_tcp_no_checksum(port, header_t_unpacked[3], header_t_unpacked[2] + content_size,
                                                       0, 0, 0, 0, 1)
            header_t = generate_header_tcp_checksum(header_t, port, header_t_unpacked[3],
                                                    header_t_unpacked[2] + content_size, 0, 0, 0, 0, 1, s_ip, d_ip,
                                                    '')
            tear = header_i + header_t + bytes('', 'utf-8')
            sock_s.sendto(tear, (d_ip, 0))

        if (header_t_unpacked[5] == 17 or header_t_unpacked[5] == 25) and header_t_unpacked[
            1] == port and address_destination == d_ip and content_size == 0:
            header_i = generate_header_ip(54322, s_ip, d_ip)
            CWND = set_congestion_control(CWND, AWND, True)
            data_in_finpacket = ''

            header_t = generate_header_tcp_no_checksum(port, header_t_unpacked[3], header_t_unpacked[2] + 1, 1, 0, 0, 0,
                                                       1)
            header_t = generate_header_tcp_checksum(header_t, port, header_t_unpacked[3], header_t_unpacked[2] + 1,
                                                    1, 0, 0, 0, 1, s_ip, d_ip, data_in_finpacket)
            packet = header_i + header_t + bytes(data_in_finpacket, 'utf-8')
            sock_s.sendto(packet, (d_ip, 0))
            write(file_name, res)
            break
        elif header_t_unpacked[1] == port and address_destination == d_ip and content_size == 0 and count > 0:
            write(file_name, res)
            break


'''
    Function: runs program
    Parameters: 
        None
    Returns: None
'''


def run(args):
    os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
    buffer = 65565
    port = random.randint(100, 65565)
    url = args.url
    split = urlsplit(url)
    host = split.netloc
    s_ip = client_ip()
    d_ip = socket.gethostbyname(urlparse(url).hostname)
    file_name, url = parse_commandline_url(split)
    print("file name is: ", file_name)
    print("url is: ", url)
    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error:
        print('Cant make socket')
        sys.exit()
    syn(send_sock, s_ip, d_ip, port)
    header_t = syn_ack_and_ack(send_sock, recv_sock, buffer, s_ip, d_ip, port)
    send_get_request(send_sock, s_ip, d_ip, port, header_t, url, host)
    download(send_sock, recv_sock, buffer, s_ip, d_ip, port, file_name)
    send_sock.close()
    recv_sock.close()
    sys.exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='rawhttpget')
    parser.add_argument('url', type=str)
    args = parser.parse_args()
    run(args)
