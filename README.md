Fetcher is a program that automates analysis of files for malicious content using static analysis techniques and famous APIs.  

## Installation  
  
chmod +x install.sh  
./install.sh  

## Usage  

usage: fetcher.py [-h] -f FILE  
  
optional arguments:  
&emsp;&emsp;&emsp;-h,&emsp;--help&emsp;&emsp;&emsp;show this help message and exit  
  
required named arguments:  
&emsp;&emsp;&emsp;-f FILE,&emsp;--file&emsp;FILE&emsp;input a file for Analysis  
&emsp;&emsp;&emsp;-d DIRECTORY,&emsp;--directory&emsp;DIRECTORY&emsp;input a directory for Analysis (15s delay)  
&emsp;&emsp;&emsp;-u URL,&emsp;--url&emsp;URL&emsp;input a url for Analysis  
  
Examples:  
  
&emsp;&emsp;&emsp;fetcher.py -f malware.vbs  
&emsp;&emsp;&emsp;fetcher.py -d directory/  
&emsp;&emsp;&emsp;fetcher.py -u maliciouswebsite.io  

## Docker  
  
# Prerequisites
  
Docker engine  
  
# Usage  
  
docker pull grt5/fetcher  
  
docker run -it fetcher bash  
  
- To copy a malicious file to the container:  
  
docker cp <SRC_PATH> <CONTAINER>:/fetcher/<DEST_PATH>  
