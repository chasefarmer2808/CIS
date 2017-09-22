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

############
#GLOBAL VARS
DEFAULT_PORT = 9999
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

  if args.server is not False:
    global server_s
    server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_s.bind(('', args.port))
    server_s.listen(1) #Only one connection at a time
    s, remote_addr = server_s.accept()
    server_s.close()
    logger.debug("Connection received from " + str(remote_addr))

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
