from datetime import datetime
import time
import os
from modules.APIs.urlscan import *
from modules.extras.args import *
from modules.extras.colors import *
from prettytable import PrettyTable

def urlscan():
    url_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")
    us_json = us_call_API()
    
    if us_json["message"] == "Submission successful":
        os.makedirs('API_results/urlscan/', exist_ok = True)
        url_api = us_json["api"]
        with open('API_results/urlscan/{'+url.replace('/', '_')+'}{'+url_stamp+'}.json', 'w') as f:
            time.sleep(11)
            api2_response = requests.get(url_api)
            f.write(json.dumps(json.loads(api2_response.content), sort_keys=False, indent=4))
            f.flush() 
        print(color.PURPLE+"[~] URL Scan results:\n"+color.CWHITE)
        try:
            json.loads(api2_response.content)["submitter"]
            us_x = PrettyTable()
            try:us_url = json.loads(api2_response.content)["page"]["url"]
            except:us_url = "Unavailable"
            try:us_domain = json.loads(api2_response.content)["page"]["domain"]
            except:us_domain = "Unavailable"
            try:us_remote_ip = json.loads(api2_response.content)["page"]["ip"]
            except:us_remote_ip = "Unavailable"
            try:us_remote_port = json.loads(api2_response.content)["data"]["requests"][0]["response"]["response"]["remotePort"]
            except:us_remote_port = "Unavailable"
            try:us_protocol = json.loads(api2_response.content)["data"]["requests"][0]["response"]["response"]["protocol"]
            except:us_protocol = "Unavailable"
            try:us_s_protocol = json.loads(api2_response.content)["data"]["requests"][0]["response"]["response"]["securityDetails"]["protocol"]
            except:us_s_protocol = "Unavailable"
            try:us_issuer = json.loads(api2_response.content)["data"]["requests"][0]["response"]["response"]["securityDetails"]["issuer"]
            except:us_issuer = "Unavailable"
            try:us_validf = datetime.fromtimestamp(json.loads(api2_response.content)["data"]["requests"][0]["response"]["response"]["securityDetails"]["validFrom"])
            except:us_validf = "Unavailable"
            try:us_validt = datetime.fromtimestamp(json.loads(api2_response.content)["data"]["requests"][0]["response"]["response"]["securityDetails"]["validTo"])
            except:us_validt = "Unavailable"
            try:us_security = json.loads(api2_response.content)["data"]["requests"][0]["response"]["response"]["securityState"]
            except:us_security = "Unavailable"
            try:us_server = json.loads(api2_response.content)["page"]["server"]
            except:us_server = "Unavailable"
            try:us_country = json.loads(api2_response.content)["page"]["country"]
            except:us_country = "Unavailable"
            try:us_city = json.loads(api2_response.content)["page"]["city"]
            except:us_city = "Unavailable"
            try:us_asn_name = json.loads(api2_response.content)["data"]["requests"][0]["response"]["asn"]["name"]
            except:us_asn_name = "Unavailable"
            try:us_asn_reg = json.loads(api2_response.content)["data"]["requests"][0]["response"]["asn"]["registrar"]
            except:us_asn_reg = "Unavailable"
            us_x.add_column("Parameter", [color.YELLOW+"URL"+color.CWHITE, color.YELLOW+"Domain"+color.CWHITE, color.YELLOW+"Server"+color.CWHITE, color.YELLOW+"Remote IP Address"+color.CWHITE, color.YELLOW+"Remote Port"+color.CWHITE, color.YELLOW+"Protocol"+color.CWHITE, color.YELLOW+"Security"+color.CWHITE, color.YELLOW+"Security Protocol"+color.CWHITE, color.YELLOW+"Certificate Issuer"+color.CWHITE, color.YELLOW+"Certificate Valid From"+color.CWHITE, color.YELLOW+"Certificate Valid To"+color.CWHITE, color.YELLOW+"ASN Name"+color.CWHITE, color.YELLOW+"ASN Registrar"+color.CWHITE, color.YELLOW+"Country"+color.CWHITE, color.YELLOW+"City"+color.CWHITE])
            us_x.add_column("Value", [color.BLUE+str(us_url)+color.CWHITE, color.BLUE+str(us_domain)+color.CWHITE, color.BLUE+str(us_server)+color.CWHITE, color.BLUE+str(us_remote_ip)+color.CWHITE, color.BLUE+str(us_remote_port)+color.CWHITE, color.BLUE+str(us_protocol)+color.CWHITE, color.BLUE+str(us_security)+color.CWHITE, color.BLUE+str(us_s_protocol)+color.CWHITE, color.BLUE+str(us_issuer)+color.CWHITE, color.BLUE+str(us_validf)+color.CWHITE, color.BLUE+str(us_validt)+color.CWHITE, color.BLUE+str(us_asn_name)+color.CWHITE, color.BLUE+str(us_asn_reg)+color.CWHITE, color.BLUE+str(us_country)+color.CWHITE, color.BLUE+str(us_city)+color.CWHITE])
            print(us_x)
            try:us_score = json.loads(api2_response.content)["verdicts"]["overall"]["score"]
            except:us_score = "Unavailable"
            try:
                us_verdict = json.loads(api2_response.content)["verdicts"]["overall"]["malicious"]
                if str(us_verdict) == "False":
                    us_verdict = color.GREEN+"Safe"+color.CWHITE
                else:
                    us_verdict = color.RED+"Malicious"+color.CWHITE
            except:
                us_verdict = "Unavailable"
            us_verdict_x = PrettyTable()
            us_verdict_x.field_names = [color.YELLOW+"Score"+color.CWHITE, color.YELLOW+"Verdict"+color.CWHITE]
            us_verdict_x.add_row([color.BLUE+str(us_score)+color.CWHITE, us_verdict])
            print(us_verdict_x)
            
        except:
            print(color.RED+"[-] "+json.loads(api2_response.content)["message"]+color.CWHITE+"\n")


        print(color.GREEN+"[+] urlscan API response saved to: "+color.CWHITE+str(f.name)+color.CWHITE+"\n")
    else:
        print(color.RED+"[-] "+us_json["message"]+color.CWHITE+"\n")