# importing the required libraries
import socket, sys
from struct import *

'''
Finds the IP address for client
Parameters:
		    None
Returns: 
            ip: Client IP
'''


def client_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('www.ccs.neu.edu', 80))
        client_ip_address = s.getsockname()[0]
    except socket.error:
        client_ip_address = "N/A"
    s.close()
    return str(client_ip_address)


'''
Find checksum using content
Parameters:
        data: the input message
Returns: 
        checksum_: the checksum
'''


def checksum(data):
    checksum_ = 0
    for i in range(0, len(data), 2):
        wr = data[i] + (data[i + 1] << 8)
        checksum_ = checksum_ + wr
    checksum_ = (checksum_ >> 16) + (checksum_ & 0xffff)
    checksum_ = checksum_ + (checksum_ >> 16)
    checksum_ = ~checksum_ & 0xffff
    return checksum_


'''
Write into file
Parameters:
        file_name: filename
        res: dictionary containing response
Returns: 
        None
'''


def write(file_name, res):
    proper_sequence = sorted(res.keys())
    http_response = bytearray()
    for key in sorted(res):
        http_response += bytearray(res[key])

    if not http_response.startswith(bytearray("HTTP/1.1 200 OK", 'utf-8')):
        print('http request failed')
        sys.exit(1)
    else:
        file_pointer = open(file_name, "wb")
        file_pointer.write(res[proper_sequence[0]].split(bytearray('\r\n\r\n', 'utf-8'))[1])
        for item in proper_sequence[1:]:
            file_pointer.write(res[item])


'''
Get filename from command line argument. If no filename present, default to index.html
Parameters:
        url: url given through command line
Returns: 
        file name, url path
'''


def parse_commandline_url(url):
    if url.path != "":
        path = url.path
        if url.path[len(url.path) - 1] == "/":
            file_name = "index.html"
        else:
            file_name = url.path.rsplit("/", 1)[1]
    else:
        path = "/"
        file_name = "index.html"

    return file_name, path


'''
    Function: set_congestion_control() - sets the congestion window value for data transmission limit
    Parameters: 
        cwnd - the current congestion window, 
        ssthresh - the advertised window limit of the client, 
        slow_start - the flag to determine whether to reset congestion window and begin slow start
    Returns: the congestion window value
'''


def set_congestion_control(cwnd: int, ssthresh: int, slow_start=False):
    cwnd_limit = 1000
    if slow_start:
        cwnd = 1
    else:
        cwnd = min(cwnd * 2, cwnd_limit, ssthresh)

    return cwnd
