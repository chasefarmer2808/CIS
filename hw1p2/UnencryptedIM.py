#!/usr/bin/python

#Original Author : Henry Tan

import os
import sys
import argparse
import socket
import select
import logging
import signal #To kill the programs nicely
import random

from collections import deque
from Crypto.Random import random

"""
function secure_generate_random_integer(low, high)
input: low -> lower bound for range
    high -> upper bound for range
output: the a secure, random integer value used for DH
"""
def secure_generate_random_integer(low, high):
  return random.randint(low, high)

############
#GLOBAL VARS
DEFAULT_PORT = 9999
SECRET_EXP = secure_generate_random_integer(1, 1000)
G = 2
P = int("""0x00cc81ea8157352a9e9a318aac4e33
    ffba80fc8da3373fb44895109e4c3f
    f6cedcc55c02228fccbd551a504feb
    4346d2aef47053311ceaba95f6c540
    b967b9409e9f0502e598cfc71327c5
    a455e2e807bede1e0b7d23fbea054b
    951ca964eaecae7ba842ba1fc6818c
    453bf19eb9c5c86e723e69a210d4b7
    2561cab97b3fb3060b""".replace("\n", "").replace(" ", ""), 0)

s = None
server_s = None
logger = logging.getLogger('main')
###########


def parse_arguments():
  parser = argparse.ArgumentParser(description = 'A P2P IM service.')
  parser.add_argument('-c', dest='connect', metavar='HOSTNAME', type=str,
    help = 'Host to connect to')
  parser.add_argument('-s', dest='server', action='store_true',
    help = 'Run as server (on port 9999)')
  parser.add_argument('-p', dest='port', metavar='PORT', type=int,
    default = DEFAULT_PORT,
    help = 'For testing purposes - allows use of different port')

  return parser.parse_args()

def print_how_to():
  print "This program must be run with exactly ONE of the following options"
  print "-c <HOSTNAME>  : to connect to <HOSTNAME> on tcp port 9999"
  print "-s             : to run a server listening on tcp port 9999"

def sigint_handler(signal, frame):
  logger.debug("SIGINT Captured! Killing")
  global s, server_s
  if s is not None:
    s.shutdown(socket.SHUT_RDWR)
    s.close()
  if server_s is not None:
    s.close()

  quit()

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

def init():
  global s
  args = parse_arguments()

  logging.basicConfig()
  logger.setLevel(logging.CRITICAL)

  #Catch the kill signal to close the socket gracefully
  signal.signal(signal.SIGINT, sigint_handler)

  if args.connect is None and args.server is False:
    print_how_to()
    quit()

  if args.connect is not None and args.server is not False:
    print_how_to()
    quit()

  if args.connect is not None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.debug('Connecting to ' + args.connect + ' ' + str(args.port))
    s.connect((args.connect, args.port))
    do_DH_exchange(False)


  if args.server is not False:
    global server_s
    server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_s.bind(('', args.port))
    server_s.listen(1) #Only one connection at a time
    s, remote_addr = server_s.accept()
    server_s.close()
    logger.debug("Connection received from " + str(remote_addr))
    do_DH_exchange(True)


def do_DH_exchange(is_server):
    global s
    global SECRET_EXP
    print(SECRET_EXP)
    data = ""
    shared_num = compute_AB(SECRET_EXP)

    if is_server:
        s.send(str(shared_num))

        while True:
            readable, writeable, exceptional = select.select([s], [s], [s])

            if s in readable:
                data = s.recv(1024)
                break
    else:
        while True:
            readable, writeable, exceptional = select.select([s], [s], [s])

            if s in readable:
                data = s.recv(1024)
                break

        s.send(str(shared_num))

    shared_secret = compute_s(int(data), SECRET_EXP)
    print(shared_secret)

def main():
  global s
  datalen=64

  init()

  inputs = [sys.stdin, s]
  outputs = [s]

  output_buffer = deque()

  while s is not None:
    #Prevents select from returning the writeable socket when there's nothing to write
    if (len(output_buffer) > 0):
      outputs = [s]
    else:
      outputs = []

    readable, writeable, exceptional = select.select(inputs, outputs, inputs)

    if s in readable:
      data = s.recv(datalen)
      #print "received packet, length "+str(len(data))

      if ((data is not None) and (len(data) > 0)):
        sys.stdout.write(data) #Assuming that stdout is always writeable
      else:
        #Socket was closed remotely
        s.close()
        s = None

    if sys.stdin in readable:
      data = sys.stdin.readline(1024)
      if(len(data) > 0):
        output_buffer.append(data)
      else:
        #EOF encountered, close if the local socket output buffer is empty.
        if( len(output_buffer) == 0):
          s.shutdown(socket.SHUT_RDWR)
          s.close()
          s = None

    if s in writeable:
      if (len(output_buffer) > 0):
        data = output_buffer.popleft()
        bytesSent = s.send(data)
        #If not all the characters were sent, put the unsent characters back in the buffer
        if(bytesSent < len(data)):
          output_buffer.appendleft(data[bytesSent:])

    if s in exceptional:
      s.shutdown(socket.SHUT_RDWR)
      s.close()
      s = None

###########

if __name__ == "__main__":
  main()
