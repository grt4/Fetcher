#!/usr/bin/env python3
import os
import json
import time

from modules.colors import *
from modules.args import *
from modules.hashing import *

if args.file == None and args.url == None:
    parser.error("At least a file or a url should be provided")

else: 
    banner()

if args.file != None and args.url == None:

    # VirusTotal (4 per minute)
    print("[~] Running analysis on "+file.split("/")[-1]+"\n")
    from modules.APIs.vt import *

    os.makedirs('results/virus_total/', exist_ok = True)
    with open('results/virus_total/{'+file.split('/')[-1]+'}{'+vt_stamp+'}.json', 'w') as f:
        f.write(json.dumps(vt_response, sort_keys=False, indent=4))
        f.flush()
        print(color.GREEN+"[+] Virus Total API response saved to: "+color.DARKCYAN+str(f.name)+color.CWHITE)

    # Hybrid Analysis
    from modules.APIs.hybrid import *

    os.makedirs('results/hybrid_analysis/', exist_ok = True)
    with open('results/hybrid_analysis/{'+file.split('/')[-1]+'}{'+hybrid_stamp+'}.json', 'w') as f:
        f.write(json.dumps(json.loads(hybrid_response.content), sort_keys=False, indent=4))
        f.flush()
        print(color.GREEN+"[+] Hybrid analysis API response saved to: "+color.DARKCYAN+str(f.name)+color.CWHITE+"\n")

elif args.file == None and args.url != None:

# urlscan
    print("[~] Running analysis on "+url+"\n")
    from modules.APIs.urlscan import *
    
    if json_url_response["message"] == "Submission successful":
        os.makedirs('results/urlscan/', exist_ok = True)
        url_api = json_url_response["api"]
        with open('results/urlscan/{'+url.replace('/', '_')+'}{'+url_stamp+'}.json', 'w') as f:
            time.sleep(11)
            f.write(json.dumps(json.loads(requests.get(url_api).content), sort_keys=False, indent=4))
            f.flush()
            print(color.GREEN+"[+] urlscan API response saved to: "+color.DARKCYAN+str(f.name)+color.CWHITE+"\n")
    else:
        print(color.RED+"[-] "+json_url_response["message"]+color.CWHITE+"\n")

print("[~] Analysis complete")