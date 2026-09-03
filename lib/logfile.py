import errno
import ipaddress
import os

from .config import (
    ATK_ID_CIPHER,
    ATK_ID_PASS,
    ATK_ID_USRCHG,
    ATK_STR_CIPHER,
    ATK_STR_PASS,
    ATK_STR_USRCHG,
    DEFAULT_PRINT_PORTS,
)

# Anchors are looked up BY NAME in the token list, never by an absolute
# offset from the start of the line.
#
# Paid on 2026-09-03. The cipher branch read `line[9]` for the address,
# which only holds while the timestamp is exactly three tokens long
# ("Jul 01 00:00:00"). Debian 12 and anything logging through journald
# or RFC5424 write a SINGLE token instead
# ("2026-09-03T00:00:02.123456+02:00"), so every index shifted by two.
#
# Measured, same four-line sample, both formats:
#   traditional : 98.76.54.32 : 1 errors (1 invalid cipher list)
#   ISO 8601    : 5555:       : 1 errors (1 invalid cipher list)
#
# The port, colon included, was reported as an offending address. No
# error, no warning - a wrong address in a list whose whole purpose is
# to feed a ban policy.
ANCHOR_PASS = "from"
ANCHOR_CIPHER = "negotiate"
ANCHOR_USRCHG = "authenticating"
ANCHOR_OFFER = "offer:"
ANCHOR_ARROW = "->"


class LogIP:

    def __init__(self, ip):
        self.ip = ip
        self.ports = {}
        self.count = 0
        self.type_count = {
            ATK_ID_PASS: 0,
            ATK_ID_CIPHER: 0,
            ATK_ID_USRCHG: 0,
        }
        self.dates = []
        self.cipher_methods = {}
        self.users = {}
        self.usrchg_tuples = []

    def update(self, log):
        self.ports[log["port"]] = self.ports.get(log["port"], 0) + 1
        self.dates.append(log["date"])
        self.count += 1
        self.type_count[log["type"]] += 1
        if log["type"] == ATK_ID_CIPHER:
            self.cipher_methods[log["ciphers"]] = \
                self.cipher_methods.get(log["ciphers"], 0) + 1
        elif log["type"] == ATK_ID_PASS:
            self.users[log["user"]] = self.users.get(log["user"], 0) + 1
        elif log["type"] == ATK_ID_USRCHG:
            self.usrchg_tuples.append(log["tuple"])

    def display(self, nbports=DEFAULT_PRINT_PORTS, allports=False,
                printports=False):
        r = f"{self.ip} : {self.count} errors "
        e = []
        if self.type_count[ATK_ID_PASS] > 0:
            e.append(f"{self.type_count[ATK_ID_PASS]} bad password")
        if self.type_count[ATK_ID_USRCHG] > 0:
            e.append(f"{self.type_count[ATK_ID_USRCHG]} userchange exploit")
        if self.type_count[ATK_ID_CIPHER] > 0:
            e.append(f"{self.type_count[ATK_ID_CIPHER]} invalid cipher list")
        r += f"({', '.join(e)}) "
        if printports:
            r += ""
        print(r)


class LogFile:

    def __init__(self, fn, parser):
        self.fname = fn
        self.parser = parser
        self.size = os.path.getsize(self.fname)
        self.hr_size = self._filesize_hr(self.size)
        self.count = {
            ATK_ID_CIPHER: 0,
            ATK_ID_PASS: 0,
            ATK_ID_USRCHG: 0,
        }
        self.total = 0
        # Lines that matched an attack string but could not be read.
        # Counted and REPORTED - a scanner that drops what it cannot
        # understand without saying so returns a reassuring zero.
        self.unreadable = 0
        self.logs = {}

    def _filesize_hr(self, n, suffix="B"):  # thanks SO !
        for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
            if abs(n) < 1024.0:
                return f"{n:3.1f} {unit}{suffix}"
            n /= 1024.0
        return f"{n:.1f}Yi{suffix}"

    def has_content(self):
        return self.total > 0

    def print_banner(self):
        len_total = self.total
        if len_total < 1:
            print(f"{self.fname} ({self.hr_size}) : No errors found.")
            if self.unreadable:
                print(f" ! {self.unreadable} matching lines could not be "
                      "read (unexpected format)")
            return
        len_pass = self.count[ATK_ID_PASS]
        len_cipher = self.count[ATK_ID_CIPHER]
        len_usrchg = self.count[ATK_ID_USRCHG]
        errors = []
        if len_pass > 0:
            errors.append(f" * {len_pass} bad password "
                          f"({round((len_pass / len_total) * 100, 1)}%)")
        if len_cipher > 0:
            errors.append(f" * {len_cipher} invalid cipherlist "
                          f"({round((len_cipher / len_total) * 100, 1)}%)")
        if len_usrchg > 0:
            errors.append(f" * {len_usrchg} userchange exploit "
                          f"({round((len_usrchg / len_total) * 100, 1)}%)")
        err = '\n'.join(errors)
        print(f"{self.fname} ({self.hr_size}) : {len_total} errors\n{err}")
        if self.unreadable:
            print(f" ! {self.unreadable} matching lines could not be read "
                  "(unexpected format)")

    def print_logs(self):
        # The sorted list is LOCAL. It used to be assigned back over
        # `self.logs`, turning a dict into a list: a second call then
        # raised `AttributeError: 'list' object has no attribute
        # 'values'`. Measured on 2026-09-03.
        ordered = sorted(self.logs.values(), key=lambda log: log.count,
                         reverse=True)
        for i, entry in enumerate(ordered):
            if i == self.parser.lines and not self.parser.all:
                break
            entry.display()

    @staticmethod
    def _date_tokens(line):
        """Timestamp width, in TOKENS. ISO 8601 is one, syslog is three."""
        head = line[0]
        if len(head) > 10 and head[4] == "-" and head[7] == "-":
            return line[0:1]
        return line[0:3]

    @staticmethod
    def _valid_ip(candidate):
        """Second, INDEPENDENT probe on the extracted address.

        The anchors say WHERE to read; this says whether what was read
        can be an address at all. Two instruments, so a log format that
        shifts under us is refused loudly instead of listing a port
        number as an offender. `ipaddress` also brings IPv6 for free -
        sshd logs v6 clients, and the previous regexp knew only v4.
        """
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return None
        return candidate

    def parse_line(self, logline):
        line = logline.split()
        # A blank line has no first token. `_date_tokens` reads one, and
        # it runs OUTSIDE the try below - so an empty line would abort
        # the whole scan. Log files carry blank lines.
        if not line:
            return None
        if self.parser.ip and self.parser.ip not in line:
            return None
        log = {"date": self._date_tokens(line)}
        try:
            if self.parser.is_set_usrchg and ATK_STR_USRCHG in logline:
                j = line.index(ANCHOR_USRCHG)
                log["type"] = ATK_ID_USRCHG
                log["user"] = line[j + 2]
                log["ip"] = line[j + 3]
                log["port"] = line[j + 5].replace(":", "")
                k = line.index(ANCHOR_ARROW)
                log["tuple"] = (line[k + 1], line[k - 1])
            elif self.parser.is_set_cipher and ATK_STR_CIPHER in logline:
                j = line.index(ANCHOR_CIPHER)
                log["type"] = ATK_ID_CIPHER
                log["ip"] = line[j + 2]
                log["port"] = line[j + 4].replace(":", "")
                if ANCHOR_OFFER in line:
                    log["ciphers"] = line[line.index(ANCHOR_OFFER) + 1]
                else:
                    log["ciphers"] = "(not stated)"
            elif self.parser.is_set_pass and ATK_STR_PASS in logline:
                j = line.index(ANCHOR_PASS)
                log["type"] = ATK_ID_PASS
                log["user"] = line[j - 1]
                log["ip"] = line[j + 1]
                log["port"] = line[j + 3]
            else:
                return None
        except (ValueError, IndexError):
            # Truncated line, or a format these anchors do not cover.
            self.unreadable += 1
            return None
        if self._valid_ip(log["ip"]) is None:
            self.unreadable += 1
            return None
        return log

    def count_update(self, e_type):
        self.count[e_type] += 1
        self.total += 1

    def parse(self):
        # `errors="replace"` IS A SECURITY DECISION, NOT A CONVENIENCE.
        #
        # Usernames reach auth.log straight from the client. A single
        # byte that is not valid UTF-8 used to raise UnicodeDecodeError
        # in the middle of the file, and the handler below then died on
        # `e.errno` - measured on 2026-09-03,
        # `AttributeError: 'UnicodeDecodeError' object has no attribute
        # 'errno'`. Whoever can write into the log could therefore stop
        # the whole analysis with one byte. Replacing undecodable bytes
        # keeps the scan running; the address tokens are ASCII anyway.
        try:
            with open(self.fname, encoding="utf-8", errors="replace") as log:
                for line in log:
                    logip = self.parse_line(line)
                    if logip is not None:
                        ip = logip["ip"]
                        if ip not in self.logs:
                            self.logs[ip] = LogIP(ip)
                        self.logs[ip].update(logip)
                        self.count_update(logip["type"])
        except OSError as e:
            # ONLY OSError CARRIES `errno`. The blanket `except
            # Exception` used to reach `e.errno` on an IndexError and
            # crash inside its own error handler.
            print(f"{self.fname} : {os.strerror(e.errno)}")
            if e.errno in (errno.EACCES, errno.EPERM):
                print("You may want to run this script with root privileges.")
            self.parser.abort("Aborting.")
