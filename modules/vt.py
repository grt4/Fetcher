import json
from virus_total_apis import PublicApi as VirusTotalPublicApi
from modules.hashing import *
from modules.encryption import vt_plain
from modules.args import *
from datetime import datetime

vt_api_key = vt_plain
vt = VirusTotalPublicApi(vt_api_key)

stamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
response = vt.get_file_report(get_hash(file,md5))
