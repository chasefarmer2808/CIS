import os  # used for generating IV through urandom function
import sys
import argparse # for parsing command line arguments and options
import socket # for initializing and setting up client and server sockets
import select # multiplexer for different input sources
import logging # nice command line output
import signal # to kill program gracefully
import random
import hashlib # for SHA1 hashing of keys
import hmac # for generating a hashed MAC

from collections import deque
from Crypto.Cipher import AES
from Crypto import Random

# GLOBAL VARIABLES
DEFAULT_PORT = 9999
AES_BLOCK_SIZE_BYTES = 16
logger = logging.getLogger('main') # initialize the logger
s = None
server_s = None


"""
Function parse_arguments()
Input: none
Output: command line arguments passed in by user
Purpose: Initialize arg parser obj.  Configure input args.
         Read in args from command line.
"""
def parse_arguments():
    parser = argparse.ArgumentParser(description='A P2P IM service with encryption')
    parser.add_argument('-c', dest='connect', metavar='HOSTNAME', type=str, help='Host to connect to')
    parser.add_argument('-s', dest='server', action='store_true', help='Run as server (on port 9999)')
    parser.add_argument('-p', dest='port', metavar='PORT', type=int, default=DEFAULT_PORT,
                        help='For testing purposes - allows use of different port')
    parser.add_argument('-confkey', dest='conf_key', metavar='CONFKEY', type=str,
                        help='The confidentiality key for message encryption')
    parser.add_argument('-authkey', dest='auth_key', metavar='AUTHKEY', type=str,
                        help='The authentication key for message authentication')

    return parser.parse_args()

"""
Function print_how_to()
Input: none
Output: print statements
Purpose: Print helpful messages to the user
"""
def print_how_to():
  print "This program must be run with exactly ONE of the following options"
  print "-c <HOSTNAME>  : to connect to <HOSTNAME> on tcp port 9999"
  print "-s             : to run a server listening on tcp port 9999"
  print "-confkey <CONFKEY> : used to encrypt the message"
  print "-authkey <AUTHKEY> : used to generate HMAC for message authentication"

"""
Function sigint_handler(signal, frame)
Input: signal -> signal to handle
       frame -> ???
Output: void
Purpose: Gracefully handle a SIGINT exception
"""
def sigint_handler(singal, frame):
    logger.debug('SIGINT Captured!  Killing...')
    global s, server_s

    if s is not None:
        s.shutdown(socket.SHUT_RDWR)
        s.close()

    if server_s is not None:
        s.close()

    quit()

"""
Function init()
Input: none
Output: none
Purpose:
"""
def init(args):
    global s
    #args = parse_arguments()

    # Catch the kill signal to close the socket gracefully
    signal.signal(signal.SIGINT, sigint_handler)

    if args.connect is None and args.server is False:
        print_how_to()
        quit()

    if args.conf_key is None or args.auth_key is None:
        print_how_to()
        quit()

    if args.connect is not None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.debug('Connecting to ' + args.connect + ' ' + str(args.port))
        s.connect((args.connect, args.port))

    if args.server is not False:
        global server_s
        server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_s.bind(('', args.port))
        server_s.listen(1) # only one connection at a time
        s, remote_addr = server_s.accept()
        server_s.close()
        logger.debug('Connection reveived from ' + str(remote_addr))

def pad(msg, block_size):
    num_bytes = len(msg)

    if (num_bytes%block_size == 0):
        return msg

    pad_bytes = block_size - (len(msg) % block_size)

    msg += '\x08'
    msg = msg + chr(0)*(pad_bytes - 1)
    return msg

def unpad(msg):
    if (msg[-1] is not '\x00'):
        return msg

    pointer = len(msg) - 1

    while (msg[pointer] != '\x08'):
        pointer -= 1

    return msg[0:pointer]

def decompile_msg(msg):
    if (len(msg) > 36):
        iv = msg[0:16]
        new_hmac = msg[16:36]
        ciphertext = msg[36:]

        return (iv, new_hmac, ciphertext)

def compile_msg(iv, hmac, msg):
    return iv + hmac + msg

def make_special_key(key):
    res = hashlib.sha1(key).digest()
    return res[0:16]

def make_hmac(key, msg):
    return hmac.new(key, msg, hashlib.sha1).digest()

def authorize(given_hmac, authkey, plaintext):
    test_hmac = make_hmac(authkey, plaintext)

    return hmac.compare_digest(test_hmac, given_hmac)

def decrypt(confkey, authkey, msg, iv):
    prime_conf_key = make_special_key(confkey)
    prime_auth_key = make_special_key(authkey)

    decryptor = AES.new(prime_conf_key, AES.MODE_CBC, iv)
    plaintext = decryptor.decrypt(msg)
    plaintext = unpad(plaintext)

    return plaintext

def encrypt(confkey, authkey, msg):
    prime_conf_key = make_special_key(confkey)
    prime_auth_key = make_special_key(authkey)

    my_hmac = make_hmac(prime_auth_key, msg)

    msg = pad(msg, AES.block_size)

    iv = Random.new().read(AES.block_size)
    cipher = AES.new(prime_conf_key, AES.MODE_CBC, iv)
    msg = cipher.encrypt(msg.encode())

    full_msg = compile_msg(iv, my_hmac, msg)

    return full_msg


def main():
    global s
    datalen = 1024
    args = parse_arguments()

    init(args)

    inputs = [sys.stdin, s]
    outputs = [s]

    output_buffer = deque()

    while s is not None:
        # Prevent select from returning the writeable socket when there's nothing to write
        if (len(output_buffer) > 0):
            outputs = [s]
        else:
            outputs = []

        readable, writeable, exceptional = select.select(inputs, outputs, inputs)

        if s in readable:
            data = s.recv(datalen)

            if ((data is not None) and (len(data) > 0)):

                recv_iv, recv_hmac, ciphertext = decompile_msg(data)
                data = decrypt(args.conf_key, args.auth_key, ciphertext, recv_iv)

                if (not authorize(recv_hmac, make_special_key(args.auth_key), data)):
                    sys.exit('Error!  Unauthorized user!!!')

                sys.stdout.write(data)
            else:
                # Socket was closed remotely
                s.close()
                s = None

        if sys.stdin in readable: # input from the user
            data = sys.stdin.readline(1024)

            if (len(data) > 0):
                output_buffer.append(data)
            else:
                # EOF encountered, close if the lockal socket output buffer is empty
                if (len(output_buffer) == 0):
                    s.shutdown(socket.SHUT_RDWR)
                    s.close()
                    s = None

        if s in writeable:
            if (len(output_buffer) > 0):
                data = output_buffer.popleft()

                full_msg = encrypt(args.conf_key, args.auth_key, data)

                bytes_sent = len(data)
                s.send(full_msg)

                # if not all the chars were sent, put the unsend chars back in the buffer
                if (bytes_sent < len(data)):
                    output_buffer.appendleft(data[bytesSent:])

        if s in exceptional:
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            s = None

# Program start
if __name__ == "__main__":
    main()
