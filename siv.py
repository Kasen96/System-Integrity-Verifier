#!/usr/bin/env python3

# A System Integrity Verifier(SIV)

import argparse
import os
import sys
import csv
import pwd
import grp
import time
import hashlib

total_dirs = 0
total_files = 0
warnings_num = 0
HASH_LISTS = list(hashlib.algorithms_guaranteed)


def is_sub_path(directory, file):
    """
    check the location of the verification file and the report file are outside the monitored directory.
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


def traverse_dir(path):
    """
    use os.walk() to traverse directories,
    and use os.stat() to collect information,
    store it in the class FileInfo.
    :param path:
    :return: file_info
    """
    file_info = FileInfo()
    abs_path = os.path.abspath(path)
    all_dirs_files = []
    global total_dirs, total_files

    # count the number of dirs and files
    for root, dirs, files in os.walk(abs_path):
        total_dirs += len(dirs)
        total_files += len(files)
        # gather the whole dirs and files
        for f in dirs + files:
            all_dirs_files.append(os.path.join(root, f))

    # collect the info
    for file_path in sorted(all_dirs_files):
        file_stat = os.stat(file_path)

        file_info.f_path = file_path
        file_info.f_size = file_stat.st_size
        file_info.user_name = pwd.getpwuid(file_stat.st_uid).pw_name
        file_info.group_name = grp.getgrgid(file_stat.st_gid).gr_name
        file_info.access_right = oct(file_stat.st_mode)
        file_info.modified_date = time.asctime(time.localtime(file_stat.st_mtime))
        if os.path.isfile(file_path):  # is file?
            # get the checksum
            hash_obj = hashlib.new(hash_fuc)
            f_size = file_stat.st_size
            try:
                with open(file_path, mode='rb') as f:
                    while f_size:
                        content = f.read(1024)
                        hash_obj.update(content)
                        f_size -= len(content)
            except IOError:
                sys.exit(f"Unable to read the file '{file_path}'.")
            file_info.message_digest = hash_obj.hexdigest()
        else:  # is dir
            file_info.message_digest = None

        yield file_info


class FileInfo:
    """
    A single file's information.
    """
    def __init__(self, f_path=None, f_size=None, user_name=None,
                 group_name=None, access_right=None,
                 modified_date=None, message_digest=None):
        self.f_path = f_path
        self.f_size = None if not f_size else int(f_size)
        self.user_name = user_name
        self.group_name = group_name
        self.access_right = access_right
        self.modified_date = modified_date
        self.message_digest = message_digest or None

    def __bool__(self):
        return bool(self.f_path)


# command line parser
description_text = "A very simple system integrity verifier(SIV) for the Linux system."
example_text = '''
Example 1: Initialization mode
siv.py -i -D important_directory -V verificationDB.csv -R my_report.txt -H sha1
Example 2: Verification mode
siv.py -v -D important_directory -V verificationDB.csv -R my_report2.txt'''

parser = argparse.ArgumentParser(description=description_text,
                                 epilog=example_text,
                                 formatter_class=argparse.RawTextHelpFormatter)

exc_group = parser.add_mutually_exclusive_group(required=True)  # at least one argument
exc_group.add_argument('-i', dest="mode", action="store_const", const='i', help="use the initialization mode")
exc_group.add_argument('-v', dest="mode", action="store_const", const='v', help="use the verification mode")

parser.add_argument('-D', dest="monitored_dir", metavar="monitored_directory", nargs=1, required=True,
                    help="specify the path of the monitored directory")
parser.add_argument('-V', dest="verification_file", metavar="verification_file", nargs=1, required=True,
                    help="specify the path of the verification file")
parser.add_argument('-R', dest="report_file", metavar="report_file", nargs=1, required=True,
                    help="specify the path of the report file")
parser.add_argument('-H', dest="hash_fuc", nargs=1, choices=HASH_LISTS, help="specify the hash function")

args = parser.parse_args()

mode = args.mode
monitored_dir = args.monitored_dir[0]
verification_file = args.verification_file[0]
report_file = args.report_file[0]

# initialization mode
if mode == 'i':
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

    start_time = time.perf_counter()

    # create the verification file using csv file
    with open(verification_file, 'w') as verification_csv_file:
        verification_writer = csv.writer(verification_csv_file)
        verification_writer.writerow([hash_fuc])  # write into the hash function

        for f_info in traverse_dir(monitored_dir):
            verification_writer.writerow([f_info.f_path, f_info.f_size, f_info.user_name, f_info.group_name,
                                          f_info.access_right, f_info.modified_date, f_info.message_digest])

    end_time = time.perf_counter()
    total_time = end_time - start_time

    # create the report file
    with open(report_file, 'w') as wr_file:
        wr_file.write(f"The monitored directory is:          '{os.path.abspath(monitored_dir)}'.\n")
        wr_file.write(f"The verification file is:            '{os.path.abspath(verification_file)}'.\n")
        wr_file.write(f"The number of directories inside is: '{total_dirs}'.\n")
        wr_file.write(f"The number of files is:              '{total_files}'.\n")
        wr_file.write(f"The total time is:                   '{round(total_time, 6)}' seconds.\n")

    print("Finish the initialization mode.")
    print(f"The verification file is stored in the '{os.path.abspath(verification_file)}'.")
    print(f"The report file is stored in the '{os.path.abspath(report_file)}'.")

# verification mode
else:  # mode == 'v'
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

        # compare files
        with open(verification_file, 'r') as verification_csv_file, open(report_file, 'w') as wr_file:
            start_time = time.perf_counter()
            old_csv = csv.reader(verification_csv_file)
            hash_fuc = next(old_csv)[0]

            f_info = traverse_dir(monitored_dir)
            old_f_info = FileInfo(*next(old_csv, []))
            new_f_info = next(f_info, None)

            while old_f_info or new_f_info:
                # File is deleted
                if (old_f_info and not new_f_info) or (old_f_info and new_f_info
                                                       and old_f_info.f_path < new_f_info.f_path):
                    wr_file.write(f"Deleted: '{old_f_info.f_path}'.\n")
                    warnings_num += 1
                    old_f_info = FileInfo(*next(old_csv, []))
                # File is created
                elif (not old_f_info and new_f_info) or \
                    (old_f_info and new_f_info and old_f_info.f_path > new_f_info.f_path):
                    wr_file.write(f"Created: '{new_f_info.f_path}'.\n")
                    warnings_num += 1
                    new_f_info = next(f_info, None)
                # file remains
                elif old_f_info and new_f_info and old_f_info.f_path == new_f_info.f_path:
                    # different size
                    if old_f_info.f_size != new_f_info.f_size:
                        wr_file.write(f"Size changed: '{old_f_info.f_path}', \
                                      '{old_f_info.f_size}' -> '{new_f_info.f_size}'.\n")
                        warnings_num += 1
                    # different user
                    if old_f_info.user_name != new_f_info.user_name:
                        wr_file.write(f"User changed: '{old_f_info.f_path}', \
                                      '{old_f_info.user_name}' -> '{new_f_info.user_name}'.\n")
                        warnings_num += 1
                    # different group
                    if old_f_info.group_name != new_f_info.group_name:
                        wr_file.write(f"group changed: '{old_f_info.f_path}', \
                                      '{old_f_info.group_name}' -> '{new_f_info.group_name}'.\n")
                        warnings_num += 1
                    # different access right
                    if old_f_info.access_right != new_f_info.access_right:
                        wr_file.write(f"Access right changed: '{old_f_info.f_path}', \
                                      '{old_f_info.access_right}' -> '{new_f_info.access_right}'.\n")
                        warnings_num += 1
                    # different modification date
                    if old_f_info.modified_date != new_f_info.modified_date:
                        wr_file.write(f"Date changed: '{old_f_info.f_path}', \
                                      '{old_f_info.modified_date}' -> '{new_f_info.modified_date}'.\n")
                        warnings_num += 1
                    # different digest
                    if old_f_info.message_digest != new_f_info.message_digest:
                        wr_file.write(f"Digest changed: '{old_f_info.f_path}', \
                                      '{old_f_info.message_digest}' -> '{new_f_info.message_digest}'.\n")
                        warnings_num += 1

                    old_f_info = FileInfo(*next(old_csv, []))
                    new_f_info = next(f_info, None)
                else:
                    sys.exit("Error during file comparison.")

            end_time = time.perf_counter()
            total_time = end_time - start_time

            # report summary
            wr_file.write(f"The monitored directory is:                 '{os.path.abspath(monitored_dir)}'.\n")
            wr_file.write(f"The verification file is:                   '{os.path.abspath(verification_file)}'.\n")
            wr_file.write(f"The report file is:                         '{os.path.abspath(report_file)}'.\n")
            wr_file.write(f"The number of directories inside is:        '{total_dirs}'.\n")
            wr_file.write(f"The number of files is:                     '{total_files}'.\n")
            wr_file.write(f"The number of warnings is:                  '{warnings_num}'.\n")
            wr_file.write(f"The total time is:                          '{round(total_time, 6)}' seconds.\n")

        print("Finish the verification mode.")
        print(f"The report file is stored in the '{os.path.abspath(report_file)}'.")
