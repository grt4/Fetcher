from modules.security.hashing import *
from modules.security.decryption import *
from modules.extras.args import *
import requests

def ha_call_API():
    hybrid_api_key = decr_CBC(b'\x0ebU\x86\x95\xc1\x97\x1b2\xbf\xa7:\x86e\xec\xd3\x0f\xe6p\xebU4\xba\xb78\x996\xb0\xf6\xf8\x0bxz\xe3\xbf\x8b2\xd0\xe5S\xef\x8dN\xec\rr5n\xa7\xb1\xcd\x94\xfc\xec\x94\xb9\x88\xfe\x8c\x06\xfe\x9f\xf8\x13')
    headers_dict = {"user-agent":'Falcon Sandbox', "api-key": hybrid_api_key}
    return requests.get("https://hybrid-analysis.com/api/v2/overview/"+get_hash(file,sha256), headers=headers_dict)