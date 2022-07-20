# Disshect

A simple utility to parse SSH error log files.

I wrote this script to help me perfect my fail2ban setup (not2gentle, not2harsh) when I found out how much my server was hammered by bots.

### Usage

```bash
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
                        globbed to match the log files. Default : auth.log*
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
root. See config.py for customization.
```

### Install

Just clone the repo wherever you want and add a link to `disshect.py` to your path

`git clone https://github.com/CyriaqueCCN/disshect ~/utils/disshect`
`ln -s ~/utils/disshect/disshect.py ~/.local/bin/disshect`

Only uses Python's standard library

