#!/usr/bin/env python3

import json
from modules.colors import *
from modules.hashing import *
from modules.vt import *
from modules.args import *
import os

banner()

# VirusTotal (4 per minute)
os.makedirs('results/virus_total/', exist_ok = True)
with open('results/virus_total/'+file.split('/')[-1].split('.')[0]+'_'+stamp+'.json', 'w') as f:
    f.write(json.dumps(response, sort_keys=False, indent=4))


