from .config import *
from .logfile import LogFile
import glob, re

class LogParser(object):
    
    def __init__(self, args):
        self.logpath = args.logpath
        self.globfiles = args.files
        self.filenames = glob.glob(f"{self.logpath}/{self.globfiles}") 
        if self.filenames == []:
            self.abort(f"No log files found for path={self.logpath} and files={self.globfiles}")
        self.logfiles = {}
        self.lines = args.numlines
        if self.lines < 1:
            self.abort("Numbers of lines to print must be > 0.")
        self.is_set_usrchg = ATK_ID_USRCHG in args.err_types or args.err_types == "all"
        self.is_set_cipher = ATK_ID_CIPHER in args.err_types or args.err_types == "all"
        self.is_set_pass = ATK_ID_PASS in args.err_types or args.err_types == "all"
        if not self.is_set_pass and not self.is_set_cipher and not self.is_set_usrchg:
            self.abort("No valid error type given.")
        self.ip = args.ip
        if self.ip and not re.match(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$", self.ip):
            self.abort(f"Invalid IP format : {self.ip}")
        self.print_all_ports = args.allports
        self.print_x_ports = args.maxportsprint
        self.all = args.all
        self.after = args.after
        self.before = args.before
        self.display_banner = not args.quiet
        self.summary = args.summary
        self.parse_files()

    def abort(self, msg):
        exit(msg)

    def parse_files(self):
        for f in self.filenames:
            if not f.endswith(".gz"):
                self.logfiles[f] = LogFile(f, self)
                self.logfiles[f].parse()
            
    def display(self):
        last = list(self.logfiles)[-1]
        for fn, logf in self.logfiles.items():
            if self.display_banner:
                logf.print_banner()
            if not self.summary and logf.has_content():
                logf.print_logs()
            if fn != last and self.display_banner:
                print()

    def run(self):
        self.display()
