#!/usr/bin/env python3

# A System Integrity Verifier(SIV)

import argparse

description_text = "A simple system integrity verifier."
example_text = '''Example 1: Initialization mode
siv -i -D important_directory -V verificationDB -R my_report.txt -H sha1
Example 2: Verification mode
siv -v -D important_directory -V verificationDB -R my_report2.txt'''

parser = argparse.ArgumentParser(prog='siv',
                                 description=description_text,
                                 epilog=example_text,
                                 formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('-i', help='use the initialization mode')
parser.add_argument('-v', help='use the verification mode')
parser.add_argument('-D', help="specify the path of the monitored directory")
parser.add_argument('-V', help="specify the path of the verification file")
parser.add_argument('-R', help="specify the path of the report file")
parser.add_argument('-H', help="specify the hash function, 'sha1' or 'md5'")

args = parser.parse_args()
