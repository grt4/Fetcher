#!/usr/bin/env python3
import os
import time

from mods.extras.colors import *
from mods.extras.args import *

def file_analysis():
    import mods.analysis.generic as gen

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
    print(color.YELLOW+"[*] Running analysis on file "+color.CYAN+file.split("/")[-1]+color.YELLOW+" ...\n"+color.CWHITE)
    from mods.analysis.generic import *

    file_analysis()

elif args.file == None and args.directory == None and args.url != None:
    print(color.YELLOW+"[*] Running analysis on url "+color.CYAN+url+color.YELLOW+" ...\n")
    from mods.analysis.url import *
    # urlscan
    urlscan()

elif args.file == None and args.directory != None and args.url == None:
    i=0
    c=0
    second_iteration = False
    print(color.YELLOW+"[*] Running analysis on directory "+color.CYAN+directory.split("/")[-2]+color.YELLOW+" ...\n"+color.CWHITE)
    from mods.analysis.generic import *
    for subdir, dirs, files in os.walk(directory):
        for file in files:
            i+=1
    for subdir, dirs, files in os.walk(directory):
        for file in files:
            file = os.path.join(subdir, file)
            print(color.YELLOW+"[*] Running analysis on file "+color.CYAN+file.split("/")[-1]+color.YELLOW+" ...\n")
            if c != i and second_iteration:
                time.sleep(15)
            second_iteration = True

            file_analysis()

            c+=1

    print(color.BLUE+"[+] "+str(i)+" files were analyzed \n"+color.CWHITE)


print(color.GREEN+"[**] Analysis complete"+color.CWHITE)