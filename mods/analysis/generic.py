import json
import os
import subprocess
from datetime import datetime
from prettytable import PrettyTable
from textwrap import TextWrapper
import puremagic
import magic
from oletools import rtfobj
import yara
from pyaxmlparser import APK

from mods.APIs.vt import vt_call_API
from mods.APIs.hybrid import ha_call_API
from mods.extras.args import *
from mods.extras.colors import *

# VirusTotal
def vt(mal):
    vt_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")
    vt_json = vt_call_API(mal)
    os.makedirs('logs/API_results/virus_total/', exist_ok = True)
    with open('logs/API_results/virus_total/{'+mal.split('/')[-1]+'}{'+vt_stamp+'}.json', 'w') as f:
        f.write(json.dumps(vt_json, sort_keys=False, indent=4))
        f.flush()
    print(color.PURPLE+"[~] Virus Total results:\n"+color.CWHITE)
    try:
        vt_table = PrettyTable()
        vt_scan_date = vt_json["results"]["scan_date"]
        vt_scan_id = vt_json["results"]["scan_id"]
        vt_total = vt_json["results"]["total"]
        vt_positives = vt_json["results"]["positives"]
        vt_scan_md5 = vt_json["results"]["md5"]
        vt_scan_sha1 = vt_json["results"]["sha1"]
        vt_scan_sha256 = vt_json["results"]["sha256"]

        vt_table.add_column("Parameter", [color.YELLOW+"Scan date"+color.CWHITE, color.YELLOW+"Scan Id"+color.CWHITE, color.YELLOW+"MD5"+color.CWHITE, color.YELLOW+"Sha1"+color.CWHITE, color.YELLOW+"Sha256"+color.CWHITE, color.YELLOW+"Total vendor scans"+color.CWHITE, color.YELLOW+"Positive scans"+color.CWHITE, color.YELLOW+"Verdict"+color.CWHITE])
        if float(vt_positives/vt_total) > 0.25:
            vt_verdict = color.RED+"malicious"+color.CWHITE
        else:
            vt_verdict = color.GREEN+"potentially safe"+color.CWHITE
        vt_table.add_column("Value", [color.BLUE+str(vt_scan_date)+color.CWHITE, color.BLUE+str(vt_scan_id)+color.CWHITE, color.BLUE+str(vt_scan_md5)+color.CWHITE, color.BLUE+str(vt_scan_sha1)+color.CWHITE, color.BLUE+str(vt_scan_sha256)+color.CWHITE, color.BLUE+str(vt_total)+color.CWHITE, color.BLUE+str(vt_positives)+color.CWHITE, vt_verdict])
        vt_table.align = 'l'
        print(vt_table)
    except:
        try:
            print(color.RED+"[-] "+str(vt_json["error"])+color.CWHITE)
        except:
            print(color.RED+"[-] "+str(vt_json["results"]["verbose_msg"])+color.CWHITE)

    print("[+] Virus Total API response saved to "+color.CYAN+color.BOLD+str(f.name)+"\n"+color.CWHITE)

# HybridAnalysis
def ha(mal):
    hybrid_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")
    ha_json = ha_call_API(mal)
    os.makedirs('logs/API_results/hybrid_analysis/', exist_ok = True)
    with open('logs/API_results/hybrid_analysis/{'+mal.split('/')[-1]+'}{'+hybrid_stamp+'}.json', 'w') as f:
        f.write(json.dumps(json.loads(ha_json.content), sort_keys=False, indent=4))
        f.flush()
    print(color.PURPLE+"[~] Hybrid Analysis results:\n"+color.CWHITE)
    try:
        ha_table = PrettyTable()
        hybrid_date = json.loads(ha_json.content)["analysis_start_time"]
        hybrid_size = json.loads(ha_json.content)["size"]
        hybrid_score = json.loads(ha_json.content)["threat_score"]
        hybrid_verdict = json.loads(ha_json.content)["verdict"]
        hybrid_type = json.loads(ha_json.content)["type_short"][0]
        try:hybrid_ext = json.loads(ha_json.content)["type_short"][1]
        except: hybrid_ext = "Unavailable"
        hybrid_arch = json.loads(ha_json.content)["architecture"]

        if str(hybrid_verdict) == "malicious":
            hybrid_verdict = color.RED+str(hybrid_verdict)+color.CWHITE
        else:
            hybrid_verdict = color.GREEN+str(hybrid_verdict)+color.CWHITE

        ha_table.add_column("Parameter", [color.YELLOW+"Scan date"+color.CWHITE, color.YELLOW+"Size"+color.CWHITE, color.YELLOW+"Type"+color.CWHITE, color.YELLOW+"Extension"+color.CWHITE, color.YELLOW+"Architecture"+color.CWHITE, color.YELLOW+"Threat Score"+color.CWHITE, color.YELLOW+"Verdict"+color.CWHITE])
        ha_table.add_column("Value",[color.BLUE+str(hybrid_date)+color.CWHITE, color.BLUE+str(hybrid_size)+color.CWHITE, color.BLUE+str(hybrid_type)+color.CWHITE, color.BLUE+str(hybrid_ext)+color.CWHITE, color.BLUE+str(hybrid_arch)+color.CWHITE, color.BLUE+str(hybrid_score)+color.CWHITE, hybrid_verdict])
        ha_table.align = 'l'
        print(ha_table)
    except:
        print(color.RED+"[-] "+str(json.loads(ha_json.content)["message"])+color.CWHITE)

    print("[+] Hybrid analysis API response saved to "+color.CYAN+color.BOLD+str(f.name)+"\n"+color.CWHITE)

# puremagic
def pm(mal):
    global uncompressed_pm_type, pm_mime_type
    uncompressed_pm_type = ""
    pm_mime_type = ""
    ext = puremagic.magic_file(mal)
    pm_table = PrettyTable()
    if len(ext) != 0:
        pm_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")
        pm_byte_match = ext[0][0]
        pm_offset = ext[0][1]
        pm_extension = ext[0][2]
        pm_name = ext[0][4]
        pm_confidence = ext[0][5]

        pm_tw = TextWrapper()
        pm_tw.width = 80
        pm_col = color.CWHITE+"\n"+color.BLUE
        uncompressed_pm_type = magic.Magic(uncompress=True).from_file(mal)
        upm = pm_col.join(pm_tw.wrap(str(uncompressed_pm_type)))+color.CWHITE

        pm_type = magic.Magic(mime=True).from_file(mal)
        pm_mime_type = str(ext[0][3])+color.CWHITE+"\n"+color.BLUE+(pm_type)

        pm_table.add_column("Parameter", [color.YELLOW+"Name"+color.CWHITE, color.YELLOW+"byte_match"+color.CWHITE, color.YELLOW+"offset"+color.CWHITE, color.YELLOW+"Extension"+color.CWHITE, color.YELLOW+"Type w/ compression"+color.CWHITE, color.YELLOW+"Type w/o compression"+color.CWHITE, color.YELLOW+"Confidence"+color.CWHITE])
        pm_table.add_column("Value", [color.BLUE+str(pm_name)+color.CWHITE, color.BLUE+str(pm_byte_match)+color.CWHITE, color.BLUE+str(pm_offset)+color.CWHITE, color.BLUE+str(pm_extension)+color.CWHITE, color.BLUE+str(pm_mime_type)+color.CWHITE, color.BLUE+upm, color.BLUE+str(pm_confidence)+color.CWHITE])
        
        os.makedirs('logs/MagicNumbers_results/', exist_ok = True)
        with open('logs/MagicNumbers_results/{'+mal.split('/')[-1]+'}{'+pm_stamp+'}.json', 'w') as f:
            f.write(pm_table.get_json_string())
            f.flush()
        print(color.PURPLE+"[~] Magic Numbers:\n"+color.CWHITE)
        pm_table.align = 'l'
        print(pm_table)
        print("[+] Magic Numbers results saved to "+color.CYAN+color.BOLD+str(f.name)+"\n"+color.CWHITE)


# oleid
def oleid(mal):
    oleid_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")
    id_cmd = "unbuffer oleid '"+str(mal)+"' | tail -n +6"
    p_id_cmd = subprocess.check_output(id_cmd, shell=True).decode().strip()
    os.makedirs('logs/oleid_results/', exist_ok = True)
    with open('logs/oleid_results/{'+mal.split('/')[-1]+'}{'+oleid_stamp+'}.md', 'w') as f:
        f.write(p_id_cmd)
        f.flush()
    print(color.PURPLE+"[~] Oledump results:\n"+color.CWHITE)
    print(p_id_cmd)
    print("[+] Oledump results saved to "+color.CYAN+color.BOLD+str(f.name)+"\n"+color.CWHITE)

# rtfobj
def rtf(mal):
    if len(list(rtfobj.rtf_iter_objects(mal))) != 0:
        rtf_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")
        rtf_cmd = "unbuffer rtfobj '"+str(mal)+"' | tail -n +6"
        p_rtf_cmd = subprocess.check_output(rtf_cmd, shell=True).decode().strip()
        os.makedirs('logs/rtf_results/', exist_ok = True)
        with open('logs/rtf_results/{'+mal.split('/')[-1]+'}{'+rtf_stamp+'}.md', 'w') as f:
            f.write(p_rtf_cmd)
            f.flush()
        print(color.PURPLE+"[~] RTF embedded objects:\n"+color.CWHITE)
        print(p_rtf_cmd)
        print("[+] RTF embedded objects saved to "+color.CYAN+color.BOLD+str(f.name)+"\n"+color.CWHITE)

# yara
def yara_matching(mal, plat):
    yara_match_indicator = 0
    path = "mods/systems/"+plat+"/yara_rules"
    rules = os.listdir(path)

    yara_table = PrettyTable()

    yara_matches = []
    for r in rules:
        try:
            rules = yara.compile(path+'/'+r)
            list_match = rules.match(mal)
            if list_match != []:
                for matched in list_match:
                    if matched.strings != []:
                        yara_matches.append(matched)
        except:
            pass

    if yara_matches != []:
        yara_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")
        yara_match_indicator += 1
        tw = TextWrapper()
        tw.width = 80
        for r in yara_matches:
            yara_table.field_names = [color.YELLOW+"Offset"+color.CWHITE, color.YELLOW+"Matched String/Byte"+color.CWHITE]
            for mm in r.strings:
                col = color.CWHITE+"\n"+color.RED
                msb = col.join(tw.wrap(str(mm[2])))+color.CWHITE
                yara_table.add_row([color.RED+str(hex(mm[0]))+color.CWHITE, color.RED+msb])
        os.makedirs('logs/yara_results/', exist_ok = True)
        with open('logs/yara_results/{'+mal.split('/')[-1]+'}{'+yara_stamp+'}.json', 'w') as f:
            f.write(yara_table.get_json_string())
            f.flush()
        print(color.RED+"[!] Matched YARA Rules for "+plat+":\n"+color.CWHITE)
        yara_table.align = 'l'
        print(yara_table)
        print("[+] Yara matches for "+plat+" saved to "+color.CYAN+color.BOLD+str(f.name)+"\n"+color.CWHITE)

    if yara_match_indicator == 0:
        print(color.GREEN+"[+] No YARA rules matched for "+plat+"\n"+color.CWHITE)


def StringAnalyzer(mal, plat):
    path = "mods/systems/"+plat+"/strings"
    string_files = os.listdir(path)
    strings_table = PrettyTable()
    matched_strings = []

    strings_cmd = "strings "+str(mal)
    p_strings_cmd = subprocess.check_output(strings_cmd, shell=True).decode().strip()

    # Iterate over strings files
    for sf in string_files:
        # Open file
        with open(path+"/"+sf, "r") as f:
            # Iterate over strings in strings file
            for line in f:
                # Iterate over strings in malware
                for i in p_strings_cmd.splitlines():
                    if line.strip() == i.strip() :
                        matched_strings.append(line.strip())
    
    if matched_strings != []:
        strings_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")
        strings_table.field_names = [color.YELLOW+"Strings Matched"+color.CWHITE]
        for m in matched_strings:
            strings_table.add_row([color.RED+str(m)+color.CWHITE])
        os.makedirs('logs/strings_results/', exist_ok = True)
        with open('logs/strings_results/{'+mal.split('/')[-1]+'}{'+strings_stamp+'}.json', 'w') as f:
            f.write(strings_table.get_json_string())
            f.flush()
        print(color.RED+"[!] Found matching strings for "+plat+":\n"+color.CWHITE)
        strings_table.align = 'l'
        print(strings_table)
        print("[+] Strings matches for "+plat+" saved to "+color.CYAN+color.BOLD+str(f.name)+"\n"+color.CWHITE)

    else:
        print(color.GREEN+"[+] No string matches found for "+plat+"\n"+color.CWHITE)


def Quark_Android(mal):
    qrk_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")
    os.makedirs('logs/quark_engine_results/', exist_ok = True)
    qrk_output = 'logs/quark_engine_results/{'+mal.split('/')[-1]+'}{'+qrk_stamp+'}.json'
    print(color.PURPLE+"[~] Quark-Engine Analysis:\n"+color.CWHITE)
    qrk_cmd = "quark -a '"+mal+"' -r mods/quark-rules/ -s -o '"+qrk_output+"'"
    subprocess.check_output(qrk_cmd, shell=True).decode().strip()

    qrk_table = PrettyTable()
    qrk_table.field_names = [color.YELLOW+"Rule"+color.CWHITE, color.YELLOW+"Confidence"+color.CWHITE, color.YELLOW+"Score"+color.CWHITE, color.YELLOW+"Weight"+color.CWHITE]
    # Opening JSON file
    qrk_f = open(qrk_output)
    
    # returns JSON object as
    qrk_data = json.load(qrk_f)
    
    # Iterating through the json
    for i in qrk_data["crimes"]:
        qrk_table.add_row([color.GREEN+str(i["crime"])+color.CWHITE, i["confidence"], i["score"], color.RED+str(i["weight"])+color.CWHITE])
    
    print("")
    qrk_table.align[color.YELLOW+"Rule"+color.CWHITE] = "l"
    print(qrk_table)
    print("")
    print(color.RED+"[!] Threat level: "+color.CWHITE+str(qrk_data["threat_level"])+color.CWHITE)
    print(color.RED+"[*] Total score: "+color.CWHITE+str(qrk_data["total_score"])+"\n"+color.CWHITE)

    print("[+] Quark-Engine results saved to "+color.CYAN+color.BOLD+str(qrk_output)+"\n"+color.CWHITE)

def apkinfo(mal):
    apk = APK(mal)
    print(color.PURPLE+"[~] APK information:\n"+color.CWHITE)
    print(color.GREEN+"[+] App name: "+color.CWHITE+apk.application+color.CWHITE)
    print(color.GREEN+"[+] Package: "+color.CWHITE+apk.package+color.CWHITE)
    print(color.GREEN+"[+] Version: "+color.CWHITE+apk.version_name+color.CWHITE)
    print(color.GREEN+"[+] Version code: "+color.CWHITE+apk.version_code+color.CWHITE)
    print(color.GREEN+"[+] Signed: "+color.CWHITE+str(apk.signed)+color.CWHITE)
    print(color.GREEN+"[+] Signed with v2 Signatures: "+color.CWHITE+str(apk.signed_v2)+color.CWHITE)
    print(color.GREEN+"[+] Signed with v1 Signatures: "+color.CWHITE+str(apk.signed_v1)+color.CWHITE)
    print(color.GREEN+"[+] Signed with v3 Signatures: "+color.CWHITE+str(apk.signed_v3)+color.CWHITE)
    print("")
