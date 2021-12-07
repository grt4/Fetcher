import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--delay", dest="delay",help="Specify a delay")
requiredNamed = parser.add_argument_group('required named arguments')
requiredNamed.add_argument("-f", "--file", dest="file",help="input a file for Analysis", required=True)
args = parser.parse_args()

# Args initiate
file = args.file