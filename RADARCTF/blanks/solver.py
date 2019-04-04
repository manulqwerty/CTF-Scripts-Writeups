#!/usr/bin/env python
import binascii
import codecs

def decode_binary_string(s):
    return ''.join(chr(int(s[i*8:i*8+8],2)) for i in range(len(s)//8))

f = open('flag.txt', 'rb')
hex_flag = f.read().encode('hex')
binary = hex_flag.replace('09', '0').replace('20', '1')

print decode_binary_string(binary) + '}'

# radar{blanks_but_not_blankz}
