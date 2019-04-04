#!/usr/bin/env python

# flag.enc and AEScipher class are given, we just have to brute force :P

from Crypto.Cipher import AES
from Crypto.Random import new as Random
from hashlib import sha256
from base64 import b64encode,b64decode
import time
import threading


class AESCipher:
  def __init__(self,data,key):
    self.block_size = 16
    self.data = data
    self.key = sha256(key.encode()).digest()[:32]
    self.pad = lambda s: s + (self.block_size - len(s) % self.block_size) * chr (self.block_size - len(s) % self.block_size)
    self.unpad = lambda s: s[:-ord(s[len(s) - 1:])]

  def encrypt(self):
    plain_text = self.pad(self.data)
    iv = Random().read(AES.block_size)
    cipher = AES.new(self.key,AES.MODE_OFB,iv)
    return b64encode(iv + cipher.encrypt(plain_text.encode())).decode()

  def decrypt(self):
    cipher_text = b64decode(self.data.encode())
    iv = cipher_text[:self.block_size]
    cipher = AES.new(self.key,AES.MODE_OFB,iv)
    return self.unpad(cipher.decrypt(cipher_text[self.block_size:])).decode()
    
    
def brute(prueba):
    data = 'vLlZz11nZdu84N57/eqkJJ0EXIlgedx41w/akqmreH7aD8pr0Bds8dNaWvbWd9MW/zeCAFzjYav+XQtyv6eijA=='
    try:
        result = AESCipher(data, prueba.strip()).decrypt()
        if 'radar' in result:
            print result
    except:
        pass

path = '/usr/share/wordlists/rockyou.txt'
with open(path, 'r') as f:
    lines = f.readlines()
    for i in lines:
        thread1 = threading.Thread(target=brute, args=[i,])
        thread1.start()
        time.sleep(0.01)
