# System Integrity Verifier(SIV)

import argparse

parser = argparse.ArgumentParser(description="A simple system integrity verifier.")

parser.add_argument('-i', help='initialization mode')
parser.add_argument('-v', help='verification mode')
parser.add_argument('-D', help="specify the monitored directory")
parser.add_argument('-V', help="specify the verification file")
parser.add_argument('-R', help="specify the report file")
parser.add_argument('-H', help="specify the hash function")

args = parser.parse_args()
