import glob
import ipaddress
import sys

from .config import ATK_ID_CIPHER, ATK_ID_PASS, ATK_ID_USRCHG
from .logfile import LogFile

# The error types the -t flag accepts, and the ONLY ones.
#
# The test used to be `ATK_ID_CIPHER in args.err_types`, a substring
# match on the raw string: `-t ciphers` or `-t passe` silently selected
# a type the user had not named, and a plain typo could not be told
# apart from a valid request. Membership in a set says yes or no.
ERR_TYPES = {ATK_ID_CIPHER, ATK_ID_PASS, ATK_ID_USRCHG}
ERR_TYPES_ALL = "all"


class LogParser:

    def __init__(self, args):
        self.logpath = args.logpath
        self.globfiles = args.files
        self.filenames = glob.glob(f"{self.logpath}/{self.globfiles}")
        if self.filenames == []:
            self.abort(f"No log files found for path={self.logpath} "
                       f"and files={self.globfiles}")
        self.logfiles = {}
        self.lines = args.numlines
        if self.lines < 1:
            self.abort("Numbers of lines to print must be > 0.")
        asked = self._err_types(args.err_types)
        self.is_set_usrchg = ATK_ID_USRCHG in asked
        self.is_set_cipher = ATK_ID_CIPHER in asked
        self.is_set_pass = ATK_ID_PASS in asked
        self.ip = args.ip
        if self.ip:
            try:
                ipaddress.ip_address(self.ip)
            except ValueError:
                self.abort(f"Invalid IP format : {self.ip}")
        self.print_all_ports = args.allports
        self.print_x_ports = args.maxportsprint
        self.all = args.all
        self.after = args.after
        self.before = args.before
        self.display_banner = not args.quiet
        self.summary = args.summary
        self.parse_files()

    def _err_types(self, raw):
        """Exact set membership, and every unknown name is NAMED."""
        if raw.strip() == ERR_TYPES_ALL:
            return set(ERR_TYPES)
        asked = {t.strip() for t in raw.split(",") if t.strip()}
        unknown = asked - ERR_TYPES
        if unknown:
            self.abort(f"Unknown error type(s) : {', '.join(sorted(unknown))}"
                       f". Valid : {', '.join(sorted(ERR_TYPES))}, "
                       f"{ERR_TYPES_ALL}.")
        if not asked:
            self.abort("No valid error type given.")
        return asked

    def abort(self, msg):
        # `sys.exit`, not the bare `exit`: the latter is installed by the
        # `site` module and is absent under `python -S` or in a frozen
        # build, where it raises NameError instead of exiting.
        sys.exit(msg)

    def parse_files(self):
        for f in self.filenames:
            if not f.endswith(".gz"):
                self.logfiles[f] = LogFile(f, self)
                self.logfiles[f].parse()
        # A NON-EMPTY GLOB THAT PARSES NOTHING IS NOT AN EMPTY GLOB.
        #
        # `self.filenames` held the gzipped files, so the guard above
        # passed, but every one of them was skipped and `display` then
        # died on `list(self.logfiles)[-1]` with `IndexError: list index
        # out of range`. Measured on 2026-09-03 with `-f 'auth.log*'` on
        # a directory holding only `auth.log.1.gz`. The absence has to be
        # told apart from the emptiness, and named.
        if not self.logfiles:
            ignored = len(self.filenames)
            self.abort(f"{ignored} file(s) matched but none could be "
                       f"parsed: gzipped files are ignored. Gunzip them, "
                       f"or narrow --files.")

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
