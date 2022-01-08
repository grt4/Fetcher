from datetime import datetime
import time
import os
from modules.APIs.urlscan import *
from modules.extras.args import *
from modules.extras.colors import *

def urlscan():
    url_stamp = datetime.now().strftime("%Y-%m-%d}{%H:%M:%S")
    
    
    if us_call_API()["message"] == "Submission successful":
        os.makedirs('API_results/urlscan/', exist_ok = True)
        url_api = us_call_API()["api"]
        with open('API_results/urlscan/{'+url.replace('/', '_')+'}{'+url_stamp+'}.json', 'w') as f:
            time.sleep(11)
            api2_response = requests.get(url_api)
            f.write(json.dumps(json.loads(api2_response.content), sort_keys=False, indent=4))
            f.flush() 
        try:
            url_url = json.loads(api2_response.content)["data"]["requests"][0]["request"]["request"]["url"]
            vt_total = us_call_API()["message"]
            vt_positives = us_call_API()["message"]
            print(color.YELLOW+"URL: "+color.CWHITE+str(url_url)+color.CWHITE)
            
        except:
            print(color.RED+"[-] "+us_call_API()["message"]+color.CWHITE+"\n")


        print(color.GREEN+"[+] urlscan API response saved to: "+color.CWHITE+str(f.name)+color.CWHITE+"\n")
    else:
        print(color.RED+"[-] "+us_call_API()["message"]+color.CWHITE+"\n")