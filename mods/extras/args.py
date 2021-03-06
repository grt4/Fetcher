import argparse

parser = argparse.ArgumentParser()
requiredNamed = parser.add_argument_group('required named arguments')

requiredNamed.add_argument("-f", "--file", dest="file",help="input a file for Analysis")
requiredNamed.add_argument("-d", "--directory", dest="directory",help="input a directory for Analysis (15s delay)")
requiredNamed.add_argument("-u", "--url", dest="url",help="input a url for Analysis")

args = parser.parse_args()


# Args initiate
file = args.file
directory = args.directory
url = args.url