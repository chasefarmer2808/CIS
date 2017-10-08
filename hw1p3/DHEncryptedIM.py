import os  # used for generating IV through urandom function
import sys
import argparse # for parsing command line arguments and options
import socket # for initializing and setting up client and server sockets
import select # multiplexer for different input sources
import logging # nice command line output
import signal # to kill program gracefully
import random
import hashlib # for SHA1 hashing of keys

from collections import deque
from Crypto.Cipher import AES
from Crypto.Random import random

"""
function secure_generate_random_integer(low, high)
input: low -> lower bound for range
    high -> upper bound for range
output: the a secure, random integer value used for DH
"""
def secure_generate_random_integer(low, high):
  return random.randint(low, high)

# GLOBAL VARIABLES
DEFAULT_PORT = 9999
AES_BLOCK_SIZE_BYTES = 16
SECRET_EXP = secure_generate_random_integer(1, 1000)
G = 2
P = 0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b

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
def init():
    global s
    args = parse_arguments()

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
        do_DH_exchange(is_server=False)

    if args.server is not False:
        global server_s
        server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_s.bind(('', args.port))
        server_s.listen(1) # only one connection at a time
        s, remote_addr = server_s.accept()
        server_s.close()
        logger.debug('Connection reveived from ' + str(remote_addr))
        do_DH_exchange(is_server=True)

"""
function compute_AB(exp)
input: exp -> exponent in the equation
output: A or B depending on client or server
"""
def compute_AB(exp):
    global G
    global P
    return (G**exp) % P

"""
function compute_s(base, exp)
input: base -> base value of the equation
output: s -> shared secret number
"""
def compute_s(base, exp):
    global G
    global P
    return (base**exp) % P

"""
Function pad(msg, block_size)
Input: msg -> string that is to be padded
       block_size -> determines how much to pad the message
Output: padded message
Purpose: For AES, messages must be on a 16 byte boundary
"""
def pad(msg, block_size):
    num_bytes = len(msg)

    if (num_bytes%block_size == 0):
        return msg

    pad_bytes = block_size - (len(msg) % block_size)

    msg += '\x08'
    msg = msg + chr(0)*(pad_bytes - 1)
    return msg

"""
Function unpad(msg)
Input: msg -> padded string
Output: Unpadded message
Purpose: Need to do this in order to get the plaintext
"""
def unpad(msg):
    if (msg[-1] is not '\x00'):
        return msg

    pointer = len(msg) - 1

    while (msg[pointer] != '\x08'):
        pointer -= 1

    return msg[0:pointer]

"""
Function decompile_msg(msg)
input: msg -> string with IV in the first 16 bytes
output: iv -> the iv generated by the sender of the message
purpose: the iv is needed to decrypt the message
"""
def decompile_msg(msg):
    if (len(msg) > 16):
        iv = msg[0:16]
        ciphertext = msg[16:]

    return (iv, ciphertext)

def compile_msg(iv, hmac, msg):
    return iv + hmac + msg

def make_special_key(key):

    if (type(key) is int): # DH support
        key = str(key)

    res = hashlib.sha1(key).digest()
    return res[0:16]

def encrypt(confkey, msg):
    prime_conf_key = make_special_key(confkey)

    msg = pad(msg, AES.block_size)
    iv = os.urandom(AES.block_size)
    cipher = AES.new(prime_conf_key, AES.MODE_CBC, iv)
    msg = cipher.encrypt(msg.encode())

    full_msg = compile_msg(iv, msg)

    return full_msg

def decrypt(confkey, msg, iv):
    prime_conf_key = make_special_key(confkey)

    decryptor = AES.new(prime_conf_key, AES.MODE_CBC, iv)
    plaintext = decryptor.decrypt(msg)
    plaintext = unpad(plaintext)

    return plaintext

def do_DH_exchange(is_server):
    global s
    global SECRET_EXP

    shared_num = compute_AB(SECRET_EXP)

    if is_server:
        s.send(str(shared_num))

        while True:
            readable, writeable, exceptional = select.select([s], [s], [s])

            if s in readable:
                data = s.recv(64)
                print(data)
                break
    else:
        while True:
            readable, writeable, exceptional = select.select([s], [s], [s])

            if s in readable:
                data = s.recv(64)
                print(data)
                break

        s.send(str(shared_num))

def main():
    global s
    datalen = 1024
    total_datalen = datalen + 36

    init()

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
            data = s.recv(total_datalen)
            if ((data is not None) and (len(data) > 0)):

                recv_iv, ciphertext = decompile_msg(data)
                # TODO: change args.conf_key to the hash of the DH key
                data = decrypt(args.conf_key, ciphertext, recv_iv)

                sys.stdout.write(data)
            else:
                # Socket was closed remotely
                s.close()
                s = None

        if sys.stdin in readable: # input from the user
            data = sys.stdin.readline(datalen)

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
                # TODO: change args.conf_key to hash of DH key
                full_msg = encrypt(args.conf_key, data)

                #bytes_sent = len(data)
                bytes_sent = s.send(full_msg)
                # if not all the chars were sent, put the unsend chars back in the buffer
                if (bytes_sent < len(full_msg)):
                    output_buffer.appendleft(full_msg[bytes_sent:])

        if s in exceptional:
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            s = None

# Program start
if __name__ == "__main__":
    main()
