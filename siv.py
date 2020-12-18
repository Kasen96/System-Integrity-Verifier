#!/usr/bin/env python3

# A System Integrity Verifier(SIV)

import argparse

# command line parser
description_text = "A very simple system integrity verifier(SIV) for the Linux system."
example_text = '''
Example 1: Initialization mode
siv.py -i -D important_directory -V verificationDB -R my_report.txt -H sha1
Example 2: Verification mode
siv.py -v -D important_directory -V verificationDB -R my_report2.txt'''

parser = argparse.ArgumentParser(description=description_text,
                                 epilog=example_text,
                                 formatter_class=argparse.RawTextHelpFormatter)

group = parser.add_mutually_exclusive_group(required=True)  # at least one parameter
group.add_argument('-i', dest="mode", action="store_const", const='i', help="use the initialization mode")
group.add_argument('-v', dest="mode", action="store_const", const='v', help="use the verification mode")

parser.add_argument('-D', dest="monitored_dir", metavar="monitored_directory", required=True,
                    help="specify the path of the monitored directory")
parser.add_argument('-V', dest="verification_file", metavar="verification_file", required=True,
                    help="specify the path of the verification file")
parser.add_argument('-R', dest="report_file", metavar="report_file", required=True,
                    help="specify the path of the report file")
parser.add_argument('-H', dest="hash_fuc", choices=['sha1', 'md5'], help="specify the hash function")

args = parser.parse_args()

mode = args.mode
monitored_dir = args.monitored_dir
verification_file = args.verification_file
report_file = args.report_file
hash_fuc = args.hash_fuc

print(mode)
print(monitored_dir)
print(verification_file)
print(report_file)
print(hash_fuc)
