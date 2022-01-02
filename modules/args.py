import argparse

parser = argparse.ArgumentParser()
requiredNamed = parser.add_argument_group('required named arguments')
requiredNamed.add_argument("-f", "--file", dest="file",help="input a file for Analysis", required=True)
args = parser.parse_args()

# Args initiate
file = args.file