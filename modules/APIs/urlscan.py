from modules.security.hashing import *
from modules.security.decryption import *
from modules.extras.args import *
import requests
import json

def us_call_API():
    url_api_key = decr_CFB(b'\xd0?.C\xaa\xa80C\xbc\xba\x03\xb2\tb\x17\xf0D\xc2\x00r\xc9\xe1J<\x86\xd5\xd9\x01P\x8a\xdd\xc5\xf6\xbbXo')

    headers = {'API-Key': url_api_key,'Content-Type':'application/json'}
    data = {"url": url, "visibility": "public"}
    url_response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    return json.loads(url_response.content)

