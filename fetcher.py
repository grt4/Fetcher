#!/usr/bin/env python3

import requests
import json
from hashlib import sha1, sha256, md5
import argparse

# Variables


# Arguments
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--delay", dest="delay",help="Specify a delay")
requiredNamed = parser.add_argument_group('required named arguments')
requiredNamed.add_argument("-f", "--file", dest="file",help="input a file for Analysis", required=True)
args = parser.parse_args()

# Args initiate
file = args.file


# Hashing
def get_hash(malware, hashfunc):

    h = hashfunc()
    with open(malware,'rb') as f:
        chunk = 0
        while chunk != b'':
            chunk = f.read(1024)
            h.update(chunk)

    return h.hexdigest()

# Virustotal.com (4 per minute)

vt_api_key = 'cd2a307a5d9866398988a4edb174a9ef1d9b1d3100316534d18ccae33a2bf564'
vt_api_url = 'https://www.virustotal.com/api/v3/files'

headers = {'x-apikey' : vt_api_key}
with open(file, 'rb') as f:
  files = {'file': (file, f)}
  response = requests.post(vt_api_url, headers=headers, files=files)
print(response.content)
