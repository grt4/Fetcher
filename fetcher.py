#!/usr/bin/env python3

import json
from modules.colors import *
from modules.hashing import *
from modules.vt import *
from modules.args import *
from modules.hybrid import *
import os

banner()

# VirusTotal (4 per minute)
os.makedirs('results/virus_total/', exist_ok = True)
with open('results/virus_total/'+file.split('/')[-1].split('.')[0]+'_'+vt_stamp+'.json', 'w') as f:
    f.write(json.dumps(vt_response, sort_keys=False, indent=4))
    print(color.GREEN+"[+] Virus Total API response saved to: "+color.DARKCYAN+str(f.name)+color.CWHITE)

# Hybrid Analysis
os.makedirs('results/hybrid_analysis/', exist_ok = True)
with open('results/hybrid_analysis/'+file.split('/')[-1].split('.')[0]+'_'+hybrid_stamp+'.json', 'w') as f:
    f.write(json.dumps(json.loads(hybrid_response.content), sort_keys=False, indent=4))
    print(color.GREEN+"[+] Hybrid analysis API response saved to: "+color.DARKCYAN+str(f.name)+color.CWHITE)
