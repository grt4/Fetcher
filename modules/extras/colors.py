class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'
   CWHITE  = '\33[37m'

def banner():
    banner = color.BOLD+color.RED+'''
     _____    _       _               
    |  ___|__| |_ ___| |__   ___ _ __ 
    | |_ / _ \ __/ __| '_ \ / _ \ '__|
    |  _|  __/ || (__| | | |  __/ |   
    |_|  \___|\__\___|_| |_|\___|_|   
     {2}A Malware Static Analysis tool

        {1}by {4}Mohamed Sahbani   
        {1}& {4}Youness Ait Ichou{1}
                        
'''.format(color.PURPLE, color.CWHITE, color.GREEN, color.RED, color.BLUE, color.DARKCYAN, color.CYAN, color.YELLOW)
    print(banner)