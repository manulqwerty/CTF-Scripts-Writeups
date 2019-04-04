#!/usr/bin/env python
import string

def encode(iput):
    dicc = {}
    randkey = 5
    for i in iput:
        dicc[ord(i) - 5] = i
    return dicc

def decode(dicc, iput):
    out = ''
    for i in iput:
        if int(i) in dicc:
            out += dicc[int(i)]
    return out

dicc = encode(string.printable)


flag = '109.92.95.92.109.118.109.92.105.95.90.100.110.90.105.106.111.90.98.106.106.95.90.100.95.96.92.90.103.106.103.120'.split('.')
print decode(dicc, flag)
