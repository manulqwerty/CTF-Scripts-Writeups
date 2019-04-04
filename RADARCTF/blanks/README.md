# Blanks
Using a hex editor we see:
![alt text](https://github.com/manulqwerty/CTF-Stuff/blob/master/RADARCTF/blanks/1.png)

Let's change the '09' for '0' and '20' for '1':
```python
>>> f = open('flag.txt', 'rb')
>>> f.read().encode('hex').replace('09', '0').replace('20', '1')
'011100100110000101100100011000010111001001111011011000100110110001100001011011100110101101110011010111110110001001110101011101000101111101101110011011110111010001011111011000100110110001100001011011100110101101111010011111'
```
Now we can use an online converter, or use python:
```python
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
```
