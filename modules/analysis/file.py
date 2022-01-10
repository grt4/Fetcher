import json
import os
from datetime import datetime
import puremagic
import androguard
import magic

from modules.APIs.vt import vt_call_API
from modules.APIs.hybrid import ha_call_API
from modules.extras.args import *
from modules.extras.colors import *

    
# VirusTotal
def vt():
    vt_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")
    os.makedirs('API_results/virus_total/', exist_ok = True)
    with open('API_results/virus_total/{'+file.split('/')[-1]+'}{'+vt_stamp+'}.json', 'w') as f:
        f.write(json.dumps(vt_call_API(), sort_keys=False, indent=4))
        f.flush()
    try:
        vt_scan_date = vt_call_API()["results"]["scan_date"]
        vt_total = vt_call_API()["results"]["total"]
        vt_positives = vt_call_API()["results"]["positives"]
        print(color.YELLOW+"scan date: "+color.CWHITE+str(vt_scan_date)+color.CWHITE)
        print(color.YELLOW+"total scans: "+color.CWHITE+str(vt_total)+color.CWHITE)
        print(color.YELLOW+"positives: "+color.CWHITE+str(vt_positives)+color.CWHITE)
        if float(vt_positives/vt_total) > 0.25:
            print(color.YELLOW+"verdict: "+color.RED+"malicious"+color.CWHITE)
        else:
            print(color.YELLOW+"verdict: "+color.GREEN+"potentially safe"+color.CWHITE)
    except:
        print(color.RED+"[-] "+str(vt_call_API()["results"]["verbose_msg"])+color.CWHITE)

    print(color.GREEN+"[+] Virus Total API response saved to: "+color.CWHITE+str(f.name)+"\n"+color.CWHITE)

# HybridAnalysis
def ha():
    hybrid_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")
    os.makedirs('API_results/hybrid_analysis/', exist_ok = True)
    with open('API_results/hybrid_analysis/{'+file.split('/')[-1]+'}{'+hybrid_stamp+'}.json', 'w') as f:
        f.write(json.dumps(json.loads(ha_call_API().content), sort_keys=False, indent=4))
        f.flush()
    try:
        hybrid_size = json.loads(ha_call_API().content)["size"]
        hybrid_score = json.loads(ha_call_API().content)["threat_score"]
        hybrid_verdict = json.loads(ha_call_API().content)["verdict"]
        hybrid_type = json.loads(ha_call_API().content)["type_short"][0]
        hybrid_ext = json.loads(ha_call_API().content)["type_short"][1]
        hybrid_arch = json.loads(ha_call_API().content)["architecture"]
        print(color.YELLOW+"size: "+color.CWHITE+str(hybrid_size)+color.CWHITE)
        print(color.YELLOW+"architecture: "+color.CWHITE+str(hybrid_arch)+color.CWHITE)
        print(color.YELLOW+"type: "+color.CWHITE+str(hybrid_type)+", "+str(hybrid_ext)+color.CWHITE)
        print(color.YELLOW+"score: "+color.CWHITE+str(hybrid_score)+color.CWHITE)
        print(color.YELLOW+"verdict: "+color.RED+str(hybrid_verdict)+color.CWHITE)
    except:
        print(color.RED+"[-] "+str(json.loads(ha_call_API().content)["message"])+color.CWHITE)

    print(color.GREEN+"[+] Hybrid analysis API response saved to: "+color.CWHITE+str(f.name)+"\n"+color.CWHITE)

# puremagic
def pm():
    ext = puremagic.magic_file(file)
    if len(ext) != 0:
        pm_byte_match = ext[0][0]
        pm_offset = ext[0][1]
        pm_extension = ext[0][2]
        pm_mime_type = ext[0][3]
        pm_name = ext[0][4]
        pm_confidence = ext[0][5]
        print(color.YELLOW+"byte_match: "+color.CWHITE+str(pm_byte_match)+color.CWHITE)
        print(color.YELLOW+"offset: "+color.CWHITE+str(pm_offset)+color.CWHITE)
        print(color.YELLOW+"extension: "+color.CWHITE+str(pm_extension)+color.CWHITE)
        print(color.YELLOW+"mime type: "+color.CWHITE+str(pm_mime_type)+color.CWHITE)
        print(color.YELLOW+"name: "+color.CWHITE+str(pm_name)+color.CWHITE)
        print(color.YELLOW+"confidence: "+color.CWHITE+str(pm_confidence)+color.CWHITE)
        print("")
    else:
        print(color.RED+"[-] Could not identify file\n"+color.CWHITE)

def pymagic():
    uncompressed_pm_type = magic.Magic(uncompress=True).from_file(file)
    pm_type = magic.Magic(mime=True).from_file(file)
    print(color.YELLOW+"type(compression uncounted for): "+color.CWHITE+str(pm_type)+color.CWHITE)
    print(color.YELLOW+"type(compression counted for): "+color.CWHITE+str(uncompressed_pm_type)+color.CWHITE)
    print("")

    if "Android" in uncompressed_pm_type:
        android()
        print("yes")

def android():
    pass