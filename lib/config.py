# Config file, change values here with caution

# you will need sudo to read the default /var/log/auth.log* files
LOG_DIR = "/var/log"

# this string will be globbed to find the matching files
FILE_GLOB = "auth.log*"

DEFAULT_PRINT_LINES = 5
DEFAULT_PRINT_PORTS = 5
DEFAULT_DONT_PRINT_FILEINFO = False

ATK_STR_PASS = "Failed password"
ATK_ID_PASS = "pass"
ATK_STR_CIPHER = "Unable to negotiate with"
ATK_ID_CIPHER = "cipher"
ATK_STR_USRCHG = "Change of username or service not allowed"
ATK_ID_USRCHG = "userchange"
