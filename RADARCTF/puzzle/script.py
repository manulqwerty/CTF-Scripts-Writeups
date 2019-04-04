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
