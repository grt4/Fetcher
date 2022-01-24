#!/usr/bin/env python3

from modules.extras.colors import *
from modules.extras.args import *

if args.file == None and args.url == None:
    parser.error("At least a file or a url should be provided")

else: 
    banner()

if args.file != None and args.url == None:
    print(color.GREEN+"[~] Running analysis on "+file.split("/")[-1]+" ...\n"+color.CWHITE)
    from modules.analysis.file import *

    #puremagic
    pm()

    # VirusTotal
    vt()

    # HybridAnalysis
    ha()


elif args.file == None and args.url != None:
    print(color.GREEN+"[~] Running analysis on "+url+" ...\n"+color.CWHITE)
    from modules.analysis.url import *
    # urlscan
    urlscan()


print("[+] Analysis complete")