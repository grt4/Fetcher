#!/usr/bin/env python3
import os
import time

from modules.extras.colors import *
from modules.extras.args import *

def file_analysis():
    import modules.analysis.generic as gen

    # puremagic
    pm(file)
    # oletools
    oleid(file)
    
    if "Rich Text Format" in gen.uncompressed_pm_type or "rtf" in gen.pm_mime_type:
        # rtfobj
        rtf(file)

    # VirusTotal
    vt(file)
    # HybridAnalysis
    ha(file)

    # android

    if "Android" in gen.uncompressed_pm_type:
        # apkinfo
        apkinfo(file)

        # quark-engine
        Quark_Android(file)

        # yara android
        print(color.PURPLE+"[~] YARA Analysis:\n"+color.CWHITE)
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


if args.file == None and args.url == None and args.directory == None:
    parser.error("At least a file or a url should be provided")

else: 
    banner()

if args.file != None and args.directory == None and args.url == None:
    print(color.YELLOW+"[*] Running analysis on file "+color.CYAN+file.split("/")[-1]+color.GREEN+" ...\n"+color.CWHITE)
    from modules.analysis.generic import *

    file_analysis()

elif args.file == None and args.directory == None and args.url != None:
    print(color.YELLOW+"[*] Running analysis on url "+color.CYAN+url+color.GREEN+" ...\n")
    from modules.analysis.url import *
    # urlscan
    urlscan()

elif args.file == None and args.directory != None and args.url == None:
    i=0
    c=0
    second_iteration = False
    print(color.YELLOW+"[*] Running analysis on directory "+color.CYAN+directory.split("/")[-2]+color.GREEN+" ...\n"+color.CWHITE)
    from modules.analysis.generic import *
    for subdir, dirs, files in os.walk(directory):
        for file in files:
            i+=1
    for subdir, dirs, files in os.walk(directory):
        for file in files:
            file = os.path.join(subdir, file)
            print(color.YELLOW+"[*] Running analysis on file "+color.CYAN+file.split("/")[-1]+color.GREEN+" ...\n")
            if c != i and second_iteration:
                time.sleep(15)
            second_iteration = True

            file_analysis()

            c+=1

    print(color.BLUE+"[+] "+str(i)+" files were analyzed "+color.CWHITE)


print("[+] Analysis complete")