#!/usr/bin/env python3

import sys
import socket
import struct

def recv_n_bytes(conn, n):
    """Helper function to receive exactly n bytes for a connection.
    Necessary because TCP connections send data through a stream of bytes. We cannot be certain if we will receive the entire
    pdu data in one packet. This fn calls recv() until the bytes received is equal to the number of bytes specified by the header
    """
    # initialize an empty byte object, used because socket connections send data as raw bytes
    data = b""
    # loop until the size of the receievd pdu is equal to the expected size as declared in the header
    while len(data) < n:
        packet = conn.recv(n - len(data)) # n - len(data) specifies we are still waiting to recieve the missing bytes
        data += packet # add received byte streamt to the total bytes of data
    return data

def server(port):
    """Create a server to receive a file over a socket"""
    # create a socket for the server program
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # bind the socket to the command line specified port. Open '' indicates we are not specifying a specific IP to listen to
        s.bind(('', int(port)))
        # listen to incoming connections from a client. Server will accept one connection
        s.listen(1)

        while True:
            # wait for connection from client
            conn, addr = s.accept()
 
            with conn:
                while True:
                    # unpack the header bytes sent from the client
                    header = recv_n_bytes(conn, 2) 
                    (length,) = struct.unpack(">H", header)
                    # if length == 0, then client finished file send and closed the connection
                    if length == 0:
                        break
                    # recieve the pdu of specifized length from the header 
                    pdu = recv_n_bytes(conn, length) 
                    if not pdu:
                        break

                    # write to the file specified from the command line
                    sys.stdout.buffer.write(pdu)
            break

def client(ip, port):
    """Create a client to send a file to remote server over a socket"""
    # create socket for the client connection
    # AF_INET indictaes socket will use IPv4
    # SOCK_STREAM indicates the socket will operate using TCP connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # connect to the server specified by the IP and port
        s.connect((ip, int(port)))

        # send data to the server
        try:
            while True:
                # read from the file specified from the command line 
                pdu = (sys.stdin.buffer.read(1024))
                if not pdu:
                    break
                # pack header bytes (2) and send PDU size
                # ">H" specifies the bytes will be sent in big-endian
                header = struct.pack(">H", len(pdu))
                # send PDU to the server
                s.sendall(header + pdu)
            # file data fully sent, but server will stay open as it is unaware. 
            # Need to send a header with a 0-sized byte data so server knows
            header = struct.pack(">H", 0)
            s.sendall(header)
        except socket.error as e:
            sys.exit(1)

def main():
    """Main entry point into the program"""
    # ensure at least 1 argument passed so no index error 
    if len(sys.argv) < 2:
        sys.exit(1)
    # parse the arguments from the command line to determine mode of uft
    if sys.argv[1] == "-l":
        # ensure correct arguments were passed
        if len(sys.argv) != 3:
            sys.exit(1)
        # first argument 'listen' -> enter server mode
        server(sys.argv[2])
    else:
        # ensure correct arguments passed
        if len(sys.argv) != 3:
            sys.exit(1)
        # first argument a IP address, enter client mode
        client(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
