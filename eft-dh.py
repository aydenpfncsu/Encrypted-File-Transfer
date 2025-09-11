#!/usr/bin/env python3

import sys
import socket
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes, random as crypto_random
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

# fixed g and h values used for Diffie-Hellman exchange
G = 2
P = 0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b

# Necessary because TCP connections send data through a stream of bytes. We cannot be certain if we will receive the entire
# pdu data in one packet. This fn calls recv() until the bytes received is equal to the number of bytes specified by the header
def recv_n_bytes(conn, n):
    """Helper function to receive exactly n bytes for a connection"""
    # initialize an empty byte object, used because socket connections send data as raw bytes
    data = b""
    # loop until the size of the receievd pdu is equal to the expected size as declared in the header
    while len(data) < n:
        packet = conn.recv(n - len(data)) # n - len(data) specifies we are still waiting to recieve the missing bytes
        if not packet: # client closed connection unexpectingly
            return None
        data += packet # add received byte streamt to the total bytes of data
    return data

def dh_exchange(conn):
    """Helper function to perform the Diffie-Hellman exchange across a connection"""
    # generate random a value s.t. 1 <= a <= p-1
    a = crypto_random.randint(1, P - 1)
    # generate A s.t. A = g^a % p
    A = pow(G, a, P)
    # pad value with zeros if not 384 digits
    A = str(A).zfill(384)
    # send public key to client, encoded in uft-8
    conn.sendall(A.encode("utf-8"))
    # receive A from the client, converting to int strips the padding
    B = int(recv_n_bytes(conn, 384).decode("utf-8"))
    # compute the shared key and hexify it
    K = '%x' % pow(B, a, P)
    # compute digest by using SHA256 hashing of the encoded K
    digest = SHA256.new(K.encode("utf-8")).digest()
    return digest[:32]

def server(port):
    """
    Create a server to receive a file over a socket

    @param port: port number for the connection
    """
    # create a socket for the server program
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # bind the socket to the command line specified port. Open '' indicates we are not specifying a specific IP to listen to
        s.bind(('', port))
        # listen to incoming connections from a client. Server will accept one connection
        s.listen(1)

        # wait for connection from client
        conn, addr = s.accept()

        with conn:
            # Run the DH exchange
            key = dh_exchange(conn)

            # now that key is constructed, begin receiving PDUs from client
            while True:
                # unpack the header bytes sent from the client
                header = recv_n_bytes(conn, 2) 
                if not header:
                    # Client completed sending file, close the server
                    break
                (length,) = struct.unpack(">H", header)
                
                # first receive the nonce (IV)
                nonce = recv_n_bytes(conn, 16)
                # receive the integrity tag
                tag = recv_n_bytes(conn, 16)
                # recieve the ciphertext of specifized length from the header; account for the 32 bytes from nonce, tag
                ciphertext = recv_n_bytes(conn, length - len(nonce) - len(tag)) 
                if not nonce or not tag or ciphertext is None:
                    break

                try:
                    # create the cipher object to decrypt the ciphertext
                    cipher = AES.new(key, AES.MODE_GCM, nonce = nonce)
                    # decrypt ciphertext and unpad (when necessary)
                    pad_plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    plaintext = unpad(pad_plaintext, 16)

                except (ValueError, KeyError) as e:
                    sys.stderr.write("Error: integrity check failed.\n")
                    break

                # write to the file specified from the command line
                sys.stdout.buffer.write(plaintext)


def client(ip, port):
    """
    Create a client to send a file to remote server over a socket

    @param ip: ip address for the connection
    @param port: port number for the connection
    """
    # create socket for the client connection
    # AF_INET indictaes socket will use IPv4
    # SOCK_STREAM indicates the socket will operate using TCP connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # connect to the server specified by the IP and port
        s.connect((ip, port))
       
        # run the DH exchange
        key = dh_exchange(s)

        try:
        # send data to the server
            while True:
                # read from the file specified from the command line 
                plaintext = (sys.stdin.buffer.read(1024))
                if not plaintext:
                    # EOF reached, break and close the client
                    break
                # pad the plaintext (if necessary)
                pad_plaintext = pad(plaintext, 16)

                # create cipher object for encryption process. Default nonce size is 16 bytes
                cipher = AES.new(key, AES.MODE_GCM) 
                # pack header bytes (2) of total length of ciphertext, tag, and nonce
                # we haven't initialized the tag yet, but know it will be 16 bytes. So hard code its size
                # ">H" specifies the bytes will be sent in big-endian
                header = struct.pack(">H", len(pad_plaintext) + 16 + len(cipher.nonce))

                # encrypt the data to get a ciphertext and a tag
                ciphertext, tag = cipher.encrypt_and_digest(pad_plaintext)
                # send header, IV, tag, and ciphertext to server 
                s.sendall(header + cipher.nonce + tag + ciphertext)

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
        server(int(sys.argv[2]))
    else:
        # ensure correct arguments passed
        if len(sys.argv) != 3:
            sys.exit(1)
        # first argument a IP address, enter client mode
        client(sys.argv[1], int(sys.argv[2]))


if __name__ == "__main__":
    main()
