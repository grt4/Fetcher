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
\t _____    _       _               
\t|  ___|__| |_ ___| |__   ___ _ __ 
\t| |_ / _ \ __/ __| '_ \ / _ \ '__|
\t|  _|  __/ || (__| | | |  __/ |   
\t|_|  \___|\__\___|_| |_|\___|_|   
                                                      
\t    {1}by {4}Mohamed Sahbani\n \t     {1}& {4}Youness Ait Ichou{1}
                        
'''.format(color.PURPLE, color.CWHITE, color.GREEN, color.RED, color.BLUE, color.DARKCYAN, color.CYAN)
    print(banner)