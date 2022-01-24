import json
import os
from datetime import datetime
import puremagic
import androguard
import magic
from prettytable import PrettyTable
import subprocess

from modules.APIs.vt import vt_call_API
from modules.APIs.hybrid import ha_call_API
from modules.extras.args import *
from modules.extras.colors import *

# VirusTotal
def vt():
    vt_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")
    vt_json = vt_call_API()
    os.makedirs('API_results/virus_total/', exist_ok = True)
    with open('API_results/virus_total/{'+file.split('/')[-1]+'}{'+vt_stamp+'}.json', 'w') as f:
        f.write(json.dumps(vt_json, sort_keys=False, indent=4))
        f.flush()
    print(color.PURPLE+"[~] Virus Total results:\n"+color.CWHITE)
    try:
        vt_x = PrettyTable()
        vt_scan_date = vt_json["results"]["scan_date"]
        vt_scan_id = vt_json["results"]["scan_id"]
        vt_total = vt_json["results"]["total"]
        vt_positives = vt_json["results"]["positives"]

        vt_scan_md5 = vt_json["results"]["md5"]
        vt_scan_sha1 = vt_json["results"]["sha1"]
        vt_scan_sha256 = vt_json["results"]["sha256"]

        vt_x.add_column("Parameter", [color.YELLOW+"Scan date"+color.CWHITE, color.YELLOW+"Scan Id"+color.CWHITE, color.YELLOW+"MD5"+color.CWHITE, color.YELLOW+"Sha1"+color.CWHITE, color.YELLOW+"Sha256"+color.CWHITE, color.YELLOW+"Total vendor scans"+color.CWHITE, color.YELLOW+"Positive scans"+color.CWHITE, color.YELLOW+"Verdict"+color.CWHITE])
        if float(vt_positives/vt_total) > 0.25:
            vt_verdict = color.RED+"malicious"+color.CWHITE
        else:
            vt_verdict = color.GREEN+"potentially safe"+color.CWHITE
        vt_x.add_column("Value", [color.BLUE+str(vt_scan_date)+color.CWHITE, color.BLUE+str(vt_scan_id)+color.CWHITE, color.BLUE+str(vt_scan_md5)+color.CWHITE, color.BLUE+str(vt_scan_sha1)+color.CWHITE, color.BLUE+str(vt_scan_sha256)+color.CWHITE, color.BLUE+str(vt_total)+color.CWHITE, color.BLUE+str(vt_positives)+color.CWHITE, vt_verdict])
        print(vt_x)
    except:
        try:
            print(color.RED+"[-] "+str(vt_json["error"])+color.CWHITE)
        except:
            print(color.RED+"[-] "+str(vt_json["results"]["verbose_msg"])+color.CWHITE)

    print(color.GREEN+"[+] Virus Total API response saved to: "+color.CWHITE+str(f.name)+"\n"+color.CWHITE)

# HybridAnalysis
def ha():
    hybrid_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")
    ha_json = ha_call_API()
    os.makedirs('API_results/hybrid_analysis/', exist_ok = True)
    with open('API_results/hybrid_analysis/{'+file.split('/')[-1]+'}{'+hybrid_stamp+'}.json', 'w') as f:
        f.write(json.dumps(json.loads(ha_json.content), sort_keys=False, indent=4))
        f.flush()
    print(color.PURPLE+"[~] Hybrid Analysis results:\n"+color.CWHITE)
    try:
        ha_x = PrettyTable()
        hybrid_date = json.loads(ha_json.content)["analysis_start_time"]
        hybrid_size = json.loads(ha_json.content)["size"]
        hybrid_score = json.loads(ha_json.content)["threat_score"]
        hybrid_verdict = json.loads(ha_json.content)["verdict"]
        hybrid_type = json.loads(ha_json.content)["type_short"][0]
        hybrid_ext = json.loads(ha_json.content)["type_short"][1]
        hybrid_arch = json.loads(ha_json.content)["architecture"]

        if str(hybrid_verdict) == "malicious":
            hybrid_verdict = color.RED+str(hybrid_verdict)+color.CWHITE
        else:
            hybrid_verdict = color.GREEN+str(hybrid_verdict)+color.CWHITE

        ha_x.add_column("Parameter", [color.YELLOW+"Scan date"+color.CWHITE, color.YELLOW+"Size"+color.CWHITE, color.YELLOW+"Type"+color.CWHITE, color.YELLOW+"Extension"+color.CWHITE, color.YELLOW+"Architecture"+color.CWHITE, color.YELLOW+"Threat Score"+color.CWHITE, color.YELLOW+"Verdict"+color.CWHITE])
        ha_x.add_column("Value",[color.BLUE+str(hybrid_date)+color.CWHITE, color.BLUE+str(hybrid_size)+color.CWHITE, color.BLUE+str(hybrid_type)+color.CWHITE, color.BLUE+str(hybrid_ext)+color.CWHITE, color.BLUE+str(hybrid_arch)+color.CWHITE, color.BLUE+str(hybrid_score)+color.CWHITE, hybrid_verdict])
        print(ha_x)
    except:
        print(color.RED+"[-] "+str(json.loads(ha_json.content)["message"])+color.CWHITE)

    print(color.GREEN+"[+] Hybrid analysis API response saved to: "+color.CWHITE+str(f.name)+"\n"+color.CWHITE)

# puremagic
def pm():
    ext = puremagic.magic_file(file)
    pm_x = PrettyTable()
    if len(ext) != 0:
        pm_byte_match = ext[0][0]
        pm_offset = ext[0][1]
        pm_extension = ext[0][2]
        pm_name = ext[0][4]
        pm_confidence = ext[0][5]
        uncompressed_pm_type = magic.Magic(uncompress=True).from_file(file)
        pm_type = magic.Magic(mime=True).from_file(file)
        pm_mime_type = str(ext[0][3])+color.CWHITE+"\n"+color.BLUE+(pm_type)

        pm_x.add_column("Parameter", [color.YELLOW+"byte_match"+color.CWHITE, color.YELLOW+"offset"+color.CWHITE, color.YELLOW+"Type w/ compression"+color.CWHITE, color.YELLOW+"Type w/o compression"+color.CWHITE, color.YELLOW+"Extension"+color.CWHITE, color.YELLOW+"Name"+color.CWHITE, color.YELLOW+"Confidence"+color.CWHITE])
        pm_x.add_column("Value", [color.BLUE+str(pm_byte_match)+color.CWHITE, color.BLUE+str(pm_offset)+color.CWHITE, color.BLUE+str(pm_mime_type)+color.CWHITE, color.BLUE+str(uncompressed_pm_type)+color.CWHITE, color.BLUE+str(pm_extension)+color.CWHITE, color.BLUE+str(pm_name)+color.CWHITE, color.BLUE+str(pm_confidence)+color.CWHITE])
        print(pm_x)
        print("")
    else:
        pass

    try:
        if "Android" in uncompressed_pm_type:
            android()
    except:
        pass

# oletools

# PE info

# Android
def android():
    pass

