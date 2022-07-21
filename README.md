# Disshect


A simple utility to parse SSH error logs.

I wrote this script to help me perfect my fail2ban setup (not2gentle, not2harsh) when I found out how much my server was hammered by bots.

It can extract info about repeating offenders and list their nature (IP address, ports of origin, exploit type, number of occurrences...)


## Usage

```
usage: disshect.py [-h] [--all] [-n NUMLINES] [-l LOGPATH] [-f FILES] [-i IP] [-P ALLPORTS]
                   [-p MAXPORTSPRINT] [-a AFTER] [-b BEFORE] [-q] [-s] [-t ERR_TYPES]

Simple utility to parse SSH error log files and extract info about the worst offenders.

optional arguments:
  -h, --help            show this help message and exit
  --all                 print all IPs found. Lots of text there.
  -n NUMLINES, --number NUMLINES
                        number of IPs to print, sorted by error total count (descending)
  -l LOGPATH, --logpath LOGPATH
                        location of the log files. Default : /var/log
  -f FILES, --files FILES
                        names of the logfiles. This takes a single string that will be
                        globbed to match the log files. gzip files will be ignored. Default : auth.log*
  -i IP, --ip IP        search for IP in the log files.
  -P ALLPORTS, --all-ports ALLPORTS
                        Not implemented
  -p MAXPORTSPRINT, --ports-max-print MAXPORTSPRINT
                        Not implemented. Default : 5
  -a AFTER, --after AFTER
                        Not implemented
  -b BEFORE, --before BEFORE
                        Not implemented
  -q, --quiet           don't print info about each log file (file size, total errors and
                        types of error found) before listing IPs. Default : False
  -s, --summary         only print file info and exit
  -t ERR_TYPES, --err-type ERR_TYPES
                        comma separated list of values for error types (currently supported
                        : 'cipher' for invalid cipherlist, 'pass' for invalid password,
                        'userchange' for preauth userchange attack). Default : all

If you want to parse classic /var/log/auth.log* files, you'll need to run this script as
root.
```

Parsing is supported for the following line types :

#### pass

Jul 01 00:00:00 HOSTNAME sshd[PID]: Failed password for root from 12.34.56.78 port 4242 ssh2

#### cipher

Jul 01 00:00:00 HOSTNAME sshd[PID]: Unable to negotiate with 12.34.56.78 port 4242: no matching key exchange method found. Their offer: diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1 [preauth]

#### userchange

Jul 01 00:00:00 HOSTNAME sshd[PID]: Disconnecting authenticating user root 12.34.56.78 port 4242: Change of username or service not allowed: (root,ssh-connection) -> (Mroot,ssh-connection) [preauth]


## Install

Just clone the repo wherever you want and add a link to `disshect.py` to your path

`git clone https://github.com/CyriaqueCCN/disshect ~/utils/disshect`

`ln -s ~/utils/disshect/disshect.py ~/.local/bin/disshect`

Only uses Python's standard library


## Example

```
$ sudo disshect

/var/log/auth.log.1 (4.0 MiB) : 9001 errors
 * 6147 bad password (68.3%)
 * 2739 invalid cipherlist (30.4%)
 * 115 userchange exploit (1.3%)
34.66.**.** : 1997 errors (1997 invalid cipher list)
164.132.***.*** : 279 errors (279 invalid cipher list)
179.60.***.*** : 208 errors (208 bad password)
92.255.**.** : 175 errors (175 bad password)
92.255.**.** : 150 errors (150 bad password)

/var/log/auth.log (1.5 MiB) : 2954 errors
 * 2584 bad password (87.5%)
 * 346 invalid cipherlist (11.7%)
 * 24 userchange exploit (0.8%)
179.60.***.*** : 162 errors (162 bad password)
101.200.***.** : 79 errors (79 bad password)
92.255.**.** : 79 errors (79 bad password)
164.132.***.*** : 72 errors (72 invalid cipher list)
92.255.**.** : 66 errors (66 bad password)
```
