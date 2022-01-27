Fetcher is a program that automates analysis of files for malicious content using static analysis techniques and famous APIs.  

## Installation  
  
chmod +x install.sh  
./install.sh  

## Usage  

usage: fetcher.py [-h] [-f FILE] [-d DIRECTORY] [-u URL]
required named arguments:
-f FILE, --file FILE  input a file for Analysis 
-d DIRECTORY, --directory DIRECTORY  input a directory for Analysis(15s delay)
-u URL, --url URL  input a url for Analysis
optional arguments:
-h, --help  show this help message and exit

Examples:
Single file analysis
    fetcher.py -f malware.vbs
Directory analysis
    fetcher.py -d directory/
URL analysis
    fetcher.py -u maliciouswebsite.io
  

## Docker  
  
  Soon  
