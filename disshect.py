#!/usr/bin/env python3

import argparse
from lib.config import *
from lib.logparser import LogParser

def parse_cmd():
    parser = argparse.ArgumentParser(description="Simple utility to parse SSH error log files and extract info about the worst offenders.", epilog="If you want to parse classic /var/log/auth.log* files, you'll need to run this script as root.\nSee config.py for customization.")
    parser.add_argument("--all", action="store_true", help="print all IPs found. Lots of text there.")
    parser.add_argument("-n", "--number", dest="numlines", type=int, default=DEFAULT_PRINT_LINES, help="number of IPs to print, sorted by error total count (descending)")
    parser.add_argument("-l", "--logpath", default=LOG_DIR, help=f"location of the log files. Default : {LOG_DIR}")
    parser.add_argument("-f", "--files", default=FILE_GLOB, help=f"names of the logfiles. This takes a single string that will be globbed to match the log files. Default : {FILE_GLOB}")
    parser.add_argument("-i", "--ip", dest="ip", type=str, default="", help="search for IP in the log files.")
    parser.add_argument("-P", "--all-ports", dest="allports", type=bool, default=False, help="Not implemented")
    parser.add_argument("-p", "--ports-max-print", dest="maxportsprint", type=int, default=DEFAULT_PRINT_PORTS, help=f"Not implemented. Default : {DEFAULT_PRINT_PORTS}")
    parser.add_argument("-a", "--after", dest="after", type=str, default="", help="Not implemented")
    parser.add_argument("-b", "--before", dest="before", type=str, default="", help="Not implemented")
    parser.add_argument("-q", "--quiet", action="store_true", default=DEFAULT_DONT_PRINT_FILEINFO, help=f"don't print info about each log file (file size, total errors and types of error found) before listing IPs. Default : {DEFAULT_DONT_PRINT_FILEINFO}")
    parser.add_argument("-s", "--summary", action="store_true", help="only print file info and exit")
    parser.add_argument("-t", "--err-type", dest="err_types", type=str, default=f"{ATK_ID_CIPHER},{ATK_ID_PASS},{ATK_ID_USRCHG}", help=f"comma separated list of values for error types (currently supported : '{ATK_ID_CIPHER}' for invalid cipherlist, '{ATK_ID_PASS}' for invalid password, '{ATK_ID_USRCHG}' for preauth userchange attack). Default : all")
    return parser.parse_args()

def main():
    args = parse_cmd()
    lgp = LogParser(args)
    lgp.run()

if __name__ == "__main__":
    main()
