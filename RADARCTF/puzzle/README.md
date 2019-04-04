**Description**
```
We love puzzle and we put a small puzzle for you ..
If you can't solve it study some math and come back again

--------------------------------------------
Challenge's URL : 
http://blackfoxs.org/radar/puzzle
```
![alt text](https://github.com/manulqwerty/CTF-Stuff/blob/master/RADARCTF/puzzle/1.png)

Checking the source, we find **<!-- don't forget to remove /puzzle_code_file.zip -->**
![alt text](https://github.com/manulqwerty/CTF-Stuff/blob/master/RADARCTF/puzzle/2.png)

On the puzzle_code_file.zip we get the index.php source code, the importan part:
```php
<?php
$puzzle = $_SERVER['HTTP_USER_AGENT'];
if (is_numeric($puzzle)){
      if (strlen($puzzle) < 4){
          if ($puzzle > 10000){
```
To bypass this we have to set a numeric **USER-AGENT > 10000** with less that 4 characteres = **9e9**
```python
#!/usr/bin/env python
import requests
import re

url = 'http://blackfoxs.org/radar/puzzle/'

headers = {
    'User-Agent': '9e9',
}

r = requests.get(url, headers=headers)
m = re.search('id="desc">(.+?)</h2>', r.text)
if m:
    found = m.group(1)
    print found

```
![alt text](https://github.com/manulqwerty/CTF-Stuff/blob/master/RADARCTF/puzzle/3.png)
