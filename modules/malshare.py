from modules.hashing import *
from modules.decryption import decr_API
from modules.args import *
from datetime import datetime
import requests

mal_api_key = '5338ca1feb45937265e7b901453953cd6afdd1ee4aecae7034b2123aacea59b3'

mal_response = requests.get("https://malshare.com/api.php?api_key="+mal_api_key+"&action=details&hash="+get_hash(file,sha256))

mal_stamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")