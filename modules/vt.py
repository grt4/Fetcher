from virus_total_apis import PublicApi as VirusTotalPublicApi
from modules.hashing import *
from modules.decryption import decr_API
from modules.args import *
from datetime import datetime

vt_api_key = decr_API(b'\x17\x95\xef\x9b\xdf\x1ckB\xb5_\xd0\x05\x83\xc3{/\xaeG\xdc\xb8\x9ex\xd3\xc9<\xef\x81\x05\xfa\xd1M\xd8\x15\x1d\x1bG\xbf\xc3-EH\\`,\x8e58\xaf\xdf\x9d\xd0\x87\x8d\xf2\xc3A\xafZ\xd3\xfb\xb4\xb0\xc9^')
vt = VirusTotalPublicApi(vt_api_key)

vt_response = vt.get_file_report(get_hash(file,md5))

vt_stamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

