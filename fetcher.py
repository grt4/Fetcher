#!/usr/bin/env python3

from modules.extras.colors import *
from modules.extras.args import *

if args.file == None and args.url == None:
    parser.error("At least a file or a url should be provided")

else: 
    banner()

if args.file != None and args.url == None:
    print(color.BLUE+"[~] Running analysis on "+file.split("/")[-1]+" ...\n"+color.CWHITE)
    from modules.analysis.file import *

    #puremagic
    print(color.PURPLE+"puremagic results:\n"+color.CWHITE)
    pm()

    #py magic
    print(color.PURPLE+"python magic results:\n"+color.CWHITE)
    pymagic()

    # VirusTotal
    print(color.PURPLE+"Virus Total results:\n"+color.CWHITE)
    try:
        vt()
    except:
        print(color.RED+"[-] Too many requests...\n"+color.CWHITE)

    # HybridAnalysis
    print(color.PURPLE+"Hybrid Analysis results:\n"+color.CWHITE)
    try:
        ha()
    except:
        print(color.RED+"[-] Too many requests...\n"+color.CWHITE)

elif args.file == None and args.url != None:
    print(color.RED+"[~] Running analysis on "+url+" ...\n"+color.CWHITE)
    from modules.analysis.url import *
    # urlscan
    print(color.PURPLE+"URL Scan results:\n"+color.CWHITE)
    try:
        urlscan()
    except:
        print(color.RED+"[-] Too many requests...\n"+color.CWHITE)

print("[+] Analysis complete")