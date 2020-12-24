# System Integrity Verifier(SIV)

A very simple system integrity verifier (SIV) for a Linux system. The goal is to detect file system modifications occurring within a directory tree. The SIV outputs statistics and warnings about changes to a report file specified by the user.

The SIV can be run either in initialization mode or in verification mode.

# Environment

MacOS / Ubuntu 18.04

Python 3.6

# Usage

``` shell
# Example 1: Initialization mode
python3 siv.py -i -D important_directory -V verificationDB.csv -R report.txt -H <digest>
```

``` shell
# Example 2: Verification mode
python3 siv.py -v -D important_directory -V verificationDB.csv -R report.txt
```

