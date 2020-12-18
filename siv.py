#!/usr/bin/env python3

# A System Integrity Verifier(SIV)

import argparse

# command line parser
description_text = "A simple system integrity verifier."
example_text = '''Example 1: Initialization mode
siv.py -i -D important_directory -V verificationDB -R my_report.txt -H sha1
Example 2: Verification mode
siv.py -v -D important_directory -V verificationDB -R my_report2.txt'''

parser = argparse.ArgumentParser(description=description_text,
                                 epilog=example_text,
                                 formatter_class=argparse.RawTextHelpFormatter)

group = parser.add_mutually_exclusive_group()
group.add_argument('-i', help='use the initialization mode', action="store_true")
group.add_argument('-v', help='use the verification mode', action="store_true")
parser.add_argument('-D', help="specify the path of the monitored directory")
parser.add_argument('-V', help="specify the path of the verification file")
parser.add_argument('-R', help="specify the path of the report file")
parser.add_argument('-H', choices=['sha1', 'md5'], help="specify the hash function")

args = parser.parse_args()
