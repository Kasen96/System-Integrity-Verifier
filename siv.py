#!/usr/bin/env python3

# A System Integrity Verifier(SIV)

import argparse
import os
import sys


def is_sub_path(directory, file):
    """
    check the location of the verification file and the report file are outside the monitored directory
    :param directory:
    :param file:
    :return: boolean
    """
    dir_path = os.path.abspath(directory)
    file_path = os.path.abspath(file)

    return file_path.startswith(dir_path)


def check_overwrite(file):
    """
    ask the user whether to overwrite the existing file.
    :param file:
    :return:
    """
    answer = input(f"Do you want to overwrite the '{file}'? [Y/n]")
    if answer.lower() == 'y' or answer.lower() == 'yes' or answer == '':
        return True
    elif answer.lower() == 'n' or answer.lower() == 'no':
        return False
    else:
        sys.exit("Unrecognized input, abort.")


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

group = parser.add_mutually_exclusive_group(required=True)  # at least one argument
group.add_argument('-i', dest="mode", action="store_const", const='i', help="use the initialization mode")
group.add_argument('-v', dest="mode", action="store_const", const='v', help="use the verification mode")

parser.add_argument('-D', dest="monitored_dir", metavar="monitored_directory", nargs=1, required=True,
                    help="specify the path of the monitored directory")
parser.add_argument('-V', dest="verification_file", metavar="verification_file", nargs=1, required=True,
                    help="specify the path of the verification file")
parser.add_argument('-R', dest="report_file", metavar="report_file", nargs=1, required=True,
                    help="specify the path of the report file")
parser.add_argument('-H', dest="hash_fuc", nargs=1, choices=['sha1', 'md5'], help="specify the hash function")

args = parser.parse_args()

mode = args.mode
monitored_dir = args.monitored_dir[0]
verification_file = args.verification_file[0]
report_file = args.report_file[0]

print("===")
print(f"the monitored dir is: {monitored_dir}")
print(f"the verification file is: {verification_file}")
print(f"the report file is: {report_file}")
print("===")

if mode == 'i':  # initialization mode
    print("Start the initialization mode.")

    if args.hash_fuc is None:
        parser.error("The hash function('-H') is required in the initialization mode.")
    hash_fuc = args.hash_fuc[0]

    # dir exists?
    if not os.path.exists(monitored_dir):
        sys.exit(f"The path '{monitored_dir}' does not exist.")
    if not os.path.isdir(monitored_dir):
        sys.exit(f"The path '{monitored_dir}' is not a directory.")
    # outside or inside?
    if is_sub_path(monitored_dir, verification_file):
        sys.exit("The verification file can not be inside the monitored directory.")
    if is_sub_path(monitored_dir, report_file):
        sys.exit("The report file can not be inside the monitored directory.")
    # file exists?
    if os.path.isdir(verification_file):
        sys.exit("The verification file can not be a directory.")
    if os.path.isfile(verification_file):
        print("The verification file already exists.")
        if not check_overwrite(verification_file):
            sys.exit("The verification file remains, abort.")
    if os.path.isdir(report_file):
        sys.exit("The report file can not be a directory.")
    if os.path.isfile(report_file):
        print("The report file already exists.")
        if not check_overwrite(report_file):
            sys.exit("The report file remains, abort.")


else:  # mode == 'v' verification mode
    if args.hash_fuc is not None:
        parser.error("The hash function('-H') can not be used in the verification mode.")
    else:
        print("Start the verification mode.")

        # outside or inside?
        if is_sub_path(monitored_dir, verification_file):
            sys.exit("The verification file can not be inside the monitored directory.")
        if is_sub_path(monitored_dir, report_file):
            sys.exit("The report file can not be inside the monitored directory.")
        # file exists?
        if os.path.isdir(verification_file):
            sys.exit("The verification file can not be a directory.")
        if not os.path.isfile(verification_file):
            sys.exit("The verification file does not exist.")
        if os.path.isdir(report_file):
            sys.exit("The report file can not be a directory.")
        if os.path.isfile(report_file):
            print("The report file already exists.")
            if not check_overwrite(report_file):
                sys.exit("The report file remains, abort.")
