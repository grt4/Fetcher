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
    print(color.CWHITE+"[~] Running analysis on "+file.split("/")[-1]+" ...\n")
    from modules.APIs.vt import *

    os.makedirs('results/virus_total/', exist_ok = True)
    with open('results/virus_total/{'+file.split('/')[-1]+'}{'+vt_stamp+'}.json', 'w') as f:
        f.write(json.dumps(vt_response, sort_keys=False, indent=4))
        f.flush()
    try:
        vt_scan_date = vt_response["results"]["scan_date"]
        vt_total = vt_response["results"]["total"]
        vt_positives = vt_response["results"]["positives"]
        print(color.PURPLE+"Virus Total results:\n")
        print(color.YELLOW+"Scan date: "+color.CWHITE+str(vt_scan_date))
        print(color.YELLOW+"Total scans: "+color.CWHITE+str(vt_total))
        print(color.YELLOW+"Positives: "+color.CWHITE+str(vt_positives))
        if float(vt_positives/vt_total) > 0.25:
            print(color.YELLOW+"Verdict: "+color.RED+"Potentially malicious")
        else:
            print(color.YELLOW+"Verdict: "+color.GREEN+"Potentially safe")
    except:
        print(color.RED+"[-] "+str(vt_response["results"]["verbose_msg"]))

    print(color.GREEN+"[+] Virus Total API response saved to: "+color.CWHITE+str(f.name)+"\n"+color.CWHITE)

    # Hybrid Analysis
    from modules.APIs.hybrid import *

    os.makedirs('results/hybrid_analysis/', exist_ok = True)
    with open('results/hybrid_analysis/{'+file.split('/')[-1]+'}{'+hybrid_stamp+'}.json', 'w') as f:
        f.write(json.dumps(json.loads(hybrid_response.content), sort_keys=False, indent=4))
        f.flush()
    try:
        hybrid_size = json.loads(hybrid_response.content)["size"]
        hybrid_score = json.loads(hybrid_response.content)["threat_score"]
        hybrid_verdict = json.loads(hybrid_response.content)["verdict"]
        hybrid_type = json.loads(hybrid_response.content)["type_short"][0]
        hybrid_ext = json.loads(hybrid_response.content)["type_short"][1]
        hybrid_arch = json.loads(hybrid_response.content)["architecture"]
        print(color.PURPLE+"Hybrid Analysis results:\n")
        print(color.YELLOW+"Size: "+color.CWHITE+str(hybrid_size))
        print(color.YELLOW+"Architecture: "+color.CWHITE+str(hybrid_arch))
        print(color.YELLOW+"Type: "+color.CWHITE+str(hybrid_type)+", "+str(hybrid_ext))
        print(color.YELLOW+"Score: "+color.CWHITE+str(hybrid_score))
        print(color.YELLOW+"Verdict: "+color.RED+str(hybrid_verdict))
    except:
        print(color.RED+"[-] "+str(json.loads(hybrid_response.content)["message"])+"\n")

    print(color.GREEN+"[+] Hybrid analysis API response saved to: "+color.CWHITE+str(f.name)+"\n"+color.CWHITE)

elif args.file == None and args.url != None:

    # urlscan
    print("[~] Running analysis on "+url+" ...\n")
    from modules.APIs.urlscan import *
    
    if json_url_response["message"] == "Submission successful":
        os.makedirs('results/urlscan/', exist_ok = True)
        url_api = json_url_response["api"]
        with open('results/urlscan/{'+url.replace('/', '_')+'}{'+url_stamp+'}.json', 'w') as f:
            time.sleep(11)
            f.write(json.dumps(json.loads(requests.get(url_api).content), sort_keys=False, indent=4))
            f.flush()


        print(color.GREEN+"[+] urlscan API response saved to: "+color.CWHITE+str(f.name)+color.CWHITE+"\n")
    else:
        print(color.RED+"[-] "+json_url_response["message"]+color.CWHITE+"\n")

print("[+] Analysis complete")