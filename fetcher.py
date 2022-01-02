#!/usr/bin/env python3

from modules.colors import *
from modules.args import *

banner()
print("[~] Running analysis on "+file.split("/")[-1]+"\n")

import os
import json
from modules.hashing import *

# VirusTotal (4 per minute)
from modules.vt import *

os.makedirs('results/virus_total/', exist_ok = True)
with open('results/virus_total/'+file.split('/')[-1].split('.')[0]+'_'+vt_stamp+'.json', 'w') as f:
    f.write(json.dumps(vt_response, sort_keys=False, indent=4))
    print(color.GREEN+"[+] Virus Total API response saved to: "+color.DARKCYAN+str(f.name)+color.CWHITE)

# Hybrid Analysis
from modules.hybrid import *

os.makedirs('results/hybrid_analysis/', exist_ok = True)
with open('results/hybrid_analysis/'+file.split('/')[-1].split('.')[0]+'_'+hybrid_stamp+'.json', 'w') as f:
    f.write(json.dumps(json.loads(hybrid_response.content), sort_keys=False, indent=4))
    print(color.GREEN+"[+] Hybrid analysis API response saved to: "+color.DARKCYAN+str(f.name)+color.CWHITE)

# Malshare
from modules.malshare import *

os.makedirs('results/malshare/', exist_ok = True)
with open('results/malshare/'+file.split('/')[-1].split('.')[0]+'_'+mal_stamp+'.json', 'w') as f:
    f.write(json.dumps(json.loads(mal_response.content), sort_keys=False, indent=4))
    print(color.GREEN+"[+] Malshare API response saved to: "+color.DARKCYAN+str(f.name)+color.CWHITE+"\n")

print("[~] Analysis complete")