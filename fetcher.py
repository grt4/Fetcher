#!/usr/bin/env python3

import requests
import json
from modules.hashing import *
from modules.vt import *
from modules.args import *

# VirusTotal (4 per minute)
with open('results/virus_total/'+file.split('/')[-1].split('.')[0]+'_'+stamp+'.json', 'w') as f:
    f.write(json.dumps(response, sort_keys=False, indent=4))


