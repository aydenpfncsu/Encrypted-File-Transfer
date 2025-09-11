#!/usr/bin/env python3

import sys
import socket
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

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

def server(port, password):
    """
    Create a server to receive a file over a socket

    @param port: port numbe for the connection
    @param password: password used to generate the symmetric key
    """
    # create a socket for the server program
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # bind the socket to the command line specified port. Open '' indicates we are not specifying a specific IP to listen to
        s.bind(('', port))
        # listen to incoming connections from a client. Server will accept one connection
        s.listen(1)

        while True:
            # wait for connection from client
            conn, addr = s.accept()
 
            with conn:
                # Before receiving pdus, get 16 byte salt from client to set up symmetic key
                salt = recv_n_bytes(conn, 16)
                # construct symmetric key using salt
                key = PBKDF2(password, salt, 32)
                # now that key is constructed, begin receiving PDUs from client
                while True:
                    # unpack the header bytes sent from the client
                    header = recv_n_bytes(conn, 2) 
                    (length,) = struct.unpack(">H", header)
                    # if length == 0, then client finished file send and closed the connection
                    if length == 0:
                        break # end of file transfer
                    
                    # first receive the nonce (IV)
                    nonce = recv_n_bytes(conn, 16)
                    # receive the integrity tag
                    tag = recv_n_bytes(conn, 16)
                    # recieve the ciphertext of specifized length from the header; account for the 32 bytes from nonce, tag
                    ciphertext = recv_n_bytes(conn, length - len(nonce) - len(tag)) 
                    if not ciphertext:
                        break

                    try:
                        # create the cipher object to decrypt the ciphertext
                        cipher = AES.new(key, AES.MODE_GCM, nonce = nonce)
                        # check for authenticity of the header
                        cipher.update(header)
                        # decrypt ciphertext and unpad (when necessary)
                        pad_plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                        plaintext = unpad(pad_plaintext, 16)

                        if plaintext == b"":
                            break

                        # print(f"Server. pad_pt{len(pad_plaintext)}; pt {len(plaintext)}; ct {len(ciphertext)}; tag {len(tag)}; nonce {len(nonce)}.", file=sys.stderr)
                    except (ValueError, KeyError) as e:
                        print(e, file=sys.stderr)
                        sys.stderr.write("Error: integrity check failed.")
                        break

                    # write to the file specified from the command line
                    sys.stdout.buffer.write(plaintext)
            break

def client(ip, port, password):
    """
    Create a client to send a file to remote server over a socket

    @param ip: ip address for the connection
    @param port: port number for the connection
    @param password: password used to generate symmetric key
    """
    # create socket for the client connection
    # AF_INET indictaes socket will use IPv4
    # SOCK_STREAM indicates the socket will operate using TCP connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # connect to the server specified by the IP and port
        s.connect((ip, port))
        
        # generate and send salt to the server, unencrypted is fine
        salt = get_random_bytes(16)
        s.sendall(salt)
        # construct the symmetric key
        key = PBKDF2(password, salt, 32)
        # send data to the server
        try:
            while True:
                # read from the file specified from the command line 
                plaintext = (sys.stdin.buffer.read(1024))
                if not plaintext:
                    plaintext = b""
                # pad the plaintext (if necessary)
                pad_plaintext = pad(plaintext, 16)

                # create cipher object for encryption process. Deafult nonce size is 16 bytes, specifying nonce just for insurance.
                cipher = AES.new(key, AES.MODE_GCM) 

                # pack header bytes (2) of total length of ciphertext, tag, and nonce
                # we haven't initialized the tag yet, but know it will be 16 bytes. So hard code its size
                # ">H" specifies the bytes will be sent in big-endian
                header = struct.pack(">H", len(pad_plaintext) + 16 + len(cipher.nonce))
                # update will authenticate the header. Unnecessary to authenticate the nonce; and the ciphertext and tag are authenticated through encryption
                cipher.update(header)

                # encrypt the data to get a ciphertext and a tag
                ciphertext, tag = cipher.encrypt_and_digest(pad_plaintext)
                # print(f"Client. pad_pt {len(pad_plaintext)}; pt {len(plaintext)}; ct {len(ciphertext)}; tag {len(tag)}; nonce {len(cipher.nonce)}.")
                # send header, IV, tag, and ciphertext to server 
                s.sendall(header + cipher.nonce + tag + ciphertext)

                # if file transfer is complete, i.e. plaintext is empty byte object, terminate client process
                if plaintext == b"":
                    break

        except socket.error as e:
            sys.exit(1)

def main():
    """Main entry point into the program"""
    # ensure correct number of arguments passed
    if len(sys.argv) != 5:
        sys.exit(1)

    # ensure correct arguments passed
    if sys.argv[1] != "-k":
        sys.exit(1)
    # store password value used to generate key
    password = sys.argv[2]

    if sys.argv[3] == "-l":
        # enter server mode; convert port number to integer
        server(int(sys.argv[4]), password)
    else:
        # enter client mode
        client(sys.argv[3], int(sys.argv[4]), password)
        


if __name__ == "__main__":
    main()
