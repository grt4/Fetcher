Program that automates analysis of files for malicious content using different APIs.  

## Installation  
  
chmod +x install.sh  
./install.sh  

## Usage  

usage: fetcher.py [-h] -f FILE  
  
optional arguments:  
&emsp;&emsp;&emsp;-h,&emsp;--help&emsp;&emsp;&emsp;show this help message and exit  
  
required named arguments:  
&emsp;&emsp;&emsp;-f FILE,&emsp;--file&emsp;FILE&emsp;&emsp;&emsp;input a file for Analysis 
&emsp;&emsp;&emsp;-d DIRECTORY,&emsp;--directory&emsp;DIRECTORY&emsp;&emsp;&emsp;input a directory for Analysis (15s delay) 
&emsp;&emsp;&emsp;-u URL,&emsp;--url&emsp;URL&emsp;&emsp;&emsp;input a url for Analysis  
  
Examples:  
  
fetcher.py -f malware.vbs  
fetcher.py -u maliciouswebsite.io  

## Docker  
  
  Soon  
  
