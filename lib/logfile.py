from .config import *
import errno, os

class LogIP(object):
    
    def __init__(self, ip):
        self.ip = ip
        self.ports = {}
        self.count = 0
        self.type_count = {
            ATK_ID_PASS : 0,
            ATK_ID_CIPHER : 0,
            ATK_ID_USRCHG : 0,
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
            self.cipher_methods[log["ciphers"]] = self.cipher_methods.get(log["ciphers"], 0) + 1
        elif log["type"] == ATK_ID_PASS:
            self.users[log["user"]] = self.users.get(log["user"], 0) + 1
        elif log["type"] == ATK_ID_USRCHG:
            self.usrchg_tuples.append(log["tuple"])

    def display(self, nbports=DEFAULT_PRINT_PORTS, allports=False, printports=False):
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
            #if allports:
            #    nbports = len(self.ports)
            #s = sorted(self.ports, key=
            r += ""
        print(r)

class LogFile(object):

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
        self.logs = {}

    def _filesize_hr(self, n, suffix="B"): # thanks SO !
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
            return
        len_pass = self.count[ATK_ID_PASS]
        len_cipher = self.count[ATK_ID_CIPHER]
        len_usrchg = self.count[ATK_ID_USRCHG]
        errors = []
        if len_pass > 0:
            errors.append(f" * {len_pass} bad password ({round((len_pass / len_total) * 100, 1)}%)")
        if len_cipher > 0:
            errors.append(f" * {len_cipher} invalid cipherlist ({round((len_cipher / len_total) * 100, 1)}%)")
        if len_usrchg > 0:
            errors.append(f" * {len_usrchg} userchange exploit ({round((len_usrchg / len_total) * 100, 1)}%)")
        err = '\n'.join(errors)
        print(f"""{self.fname} ({self.hr_size}) : {len_total} errors\n{err}""")

    def print_logs(self):
        self.logs = sorted(self.logs.values(), key=lambda log : log.count, reverse=True)
        i = 0
        for l in self.logs:
            if i == self.parser.lines and not self.parser.all:
                break
            l.display()
            i += 1

    def parse_line(self, logline):
        line = logline.split()
        if self.parser.ip and not self.parser.ip in line:
            return
        log = {"date" : line[0:3]}
        #try:
        if self.parser.is_set_usrchg and ATK_STR_USRCHG in logline:
            log["type"] = ATK_ID_USRCHG
            log["ip"] = line[-14]
            log["port"] = line[-12].replace(":", "")
            log["tuple"] = (line[-2], line[-4])
            #log["is-invalid"] = line[6] == "invalid"
        elif self.parser.is_set_cipher and ATK_STR_CIPHER in logline:
            log["type"] = ATK_ID_CIPHER
            log["ip"] = line[9]
            log["port"] = line[11].replace(":", "")
            log["ciphers"] = line[-2]
        elif self.parser.is_set_pass and ATK_STR_PASS in logline:
            log["type"] = ATK_ID_PASS
            log["ip"] = line[-4]
            log["port"] = line[-2]
            log["user"] = line[-6]
            #log["is-invalid"] = line[8] == "invalid"
        else:
            return
        #except: # bad format
        #return
        return log

    def count_update(self, e_type):
        self.count[e_type] += 1
        self.total += 1

    def parse(self):
        try:
            with open(self.fname, "r") as log:
                for line in log.readlines():
                    logip = self.parse_line(line)
                    if logip is not None:
                        ip = logip["ip"]
                        if self.logs.get(ip, "") == "":
                            self.logs[ip] = LogIP(ip)
                        self.logs[ip].update(logip)
                        self.count_update(logip["type"])
        except Exception as e:
            err = e.errno
            print(f"{self.fname} : {os.strerror(err)}")
            if e.errno == errno.EACCES or e.errno == errno.EPERM:
                print("You may want to run this script with root privileges.")
            exit("Aborting.")

