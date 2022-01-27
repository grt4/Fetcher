Fetcher is a program that automates analysis of files for malicious content using static analysis techniques and famous APIs.  

## Installation  
  
chmod +x install.sh  
./install.sh  

## Usage  

usage: fetcher.py [-h] [-f FILE] [-d DIRECTORY] [-u URL]

optional arguments:
  -h, --help  show this help message and exit  
required named arguments:
  -f FILE, --file FILE  input a file for Analysis
  -d DIRECTORY, --directory DIRECTORY
                        input a directory for Analysis
                        (15s delay)
  -u URL, --url URL     input a url for Analysis 
  
Examples:  
  
fetcher.py -f malware.vbs  
fetcher.py -d directory/  
fetcher.py -u maliciouswebsite.io  

## Docker  
  
  Soon  
  
