import json
from virus_total_apis import PublicApi as VirusTotalPublicApi
from hashing import *
from args import *


vt_api_key = 'cd2a307a5d9866398988a4edb174a9ef1d9b1d3100316534d18ccae33a2bf564'
vt = VirusTotalPublicApi(vt_api_key)

response = vt.get_file_report(get_hash(file,md5))
