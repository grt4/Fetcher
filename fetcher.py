#!/usr/bin/env python3
import os
import time

from modules.extras.colors import *
from modules.extras.args import *

if args.file == None and args.url == None and args.directory == None:
    parser.error("At least a file or a url should be provided")

else: 
    banner()

if args.file != None and args.directory == None and args.url == None:
    print(color.GREEN+"[~] Running analysis on file "+color.YELLOW+file.split("/")[-1]+color.GREEN+" ...\n"+color.CWHITE)
    from modules.analysis.generic import *

    # puremagic
    pm(file)
    # oletools
    oleid(file)
    # rtfobj
    rtf(file)
    # VirusTotal
    vt(file)
    # HybridAnalysis
    ha(file)

    # android
    import modules.analysis.generic as gen
    if "Android" in gen.uncompressed_pm_type:
        print(color.PURPLE+"[~] YARA Analysis:\n"+color.CWHITE)
        # yara android
        yara_matching(file, 'android')

    else:
        print(color.PURPLE+"[~] YARA Analysis:\n"+color.CWHITE)
        # yara windows
        yara_matching(file, 'windows')

        # yara linux
        yara_matching(file, 'linux')

        # yara os
        yara_matching(file, 'macOS')

        print(color.PURPLE+"[~] Strings Analysis:\n"+color.CWHITE)
        # strings windows
        StringAnalyzer(file, 'windows')

        # strings linux
        StringAnalyzer(file, 'linux')

        # strings os
        StringAnalyzer(file, 'macOS')

    

    

    



elif args.file == None and args.directory == None and args.url != None:
    print(color.GREEN+"[~] Running analysis on url "+color.YELLOW+url+color.GREEN+" ...\n")
    from modules.analysis.url import *
    # urlscan
    urlscan()

elif args.file == None and args.directory != None and args.url == None:
    i=0
    c=0
    print(color.GREEN+"[~] Running analysis on directory "+color.YELLOW+directory.split("/")[-2]+color.GREEN+" ...\n"+color.CWHITE)
    from modules.analysis.generic import *
    for subdir, dirs, files in os.walk(directory):
        for file in files:
            i+=1
    for subdir, dirs, files in os.walk(directory):
        for file in files:
            file = os.path.join(subdir, file)
            print(color.GREEN+"[~] Running analysis on file "+color.YELLOW+file.split("/")[-1]+color.GREEN+" ...\n")
            #puremagic
            pm(file)
            # oletools
            oleid(file)
            # rtfobj
            rtf(file)
            # VirusTotal
            vt(file)
            # HybridAnalysis
            ha(file)
            c+=1
            if c != i:
                time.sleep(15)
    print(color.BLUE+"[+] "+str(i)+" files were analyzed "+color.CWHITE)


print("[+] Analysis complete")