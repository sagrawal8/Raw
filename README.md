High Level Approach:

1. Obtain url through command line and parse it to find the host, path and filename.
2. Get IP address of client and destination.
3. Create a send and receive socket and also create TCP and IP headers.
4. Send a Syn packet.
5. Receive Syn/Ack and send ACK if criteria met, otherwise send SYN again.
6. Send HTTP get request.
7. Store server response, ie. data sent through packets.
8. Ack data received from server until FIN flag.
9. Send FIN to server.
10. Terminate connection after ACK from server.
11. Write data stored to file.

Challenges:

Header creation and checksum function.
Received S, then . then S. in 3 way handshake process which was definitely a huge problem. 
Permission denied for sending ACK after SYN_ACK. 
Random bytes being written into file, fixed by not decoding before writing and also writing in 'wb'.

Testing:

1. Made sure using tcp dump that handshake is going as predicted.
2. Tested most pages on davidchoffness.com as well as the 2mb, 10mb and 50mb files.

TCP/IP features implemented:

1. Validate Checksum
2. Source + Destination IP in packets
3. Headers fields were correctly implemented such as header length, id, version, etc.
4. Found a port for localhost.
5. 3 way handshake with sequence numbers being incremented.
6. Termination using FIN.
7. ADV Window
8. Sorting of out-of-order data received.
9. Duplicate packets discarded since data is stored in dict.
