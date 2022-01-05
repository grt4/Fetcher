from modules.hashing import *
from modules.decryption import *
from modules.args import *
from datetime import datetime
import requests
import json

url_api_key = decr_CFB(b'\xd0?.C\xaa\xa80C\xbc\xba\x03\xb2\tb\x17\xf0D\xc2\x00r\xc9\xe1J<\x86\xd5\xd9\x01P\x8a\xdd\xc5\xf6\xbbXo')

headers = {'API-Key': url_api_key,'Content-Type':'application/json'}
data = {"url": url, "visibility": "public"}
url_response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
json_url_response = json.loads(url_response.content)

url_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")