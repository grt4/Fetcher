Fetcher is a program that automates analysis of files for malicious content using static analysis techniques and famous APIs.  

## Installation  
  
chmod +x install.sh  
./install.sh  

## Usage  

-e <email>          Single validation check
-i <file in>        Dictionary
-b                  Brute-force 
-c [characters]     Characters set to bruteforce - Default is [a-z0-9.]
-t [interval]       Set time between two verifications - Default is 0.3s - range is [0-600]
-o [file out]       Ouput results to file
-h                  Help

Examples:
Single Email verification
    argus.py -e example@example.com [-t 0.1]
Dictionary verification
    argus.py -i dictionary.txt [-o results.txt] [-t 0.1]
Brute-force verification
    argus.py -b examp**3*5@example.com [-c 1g7.] [-o results.txt] [-t 0.1]
  

## Docker  
  
  Soon  
  
