splunk_query
============

Submit a query to splunk (api) via a python script.

Usage
=====
~~~~
Usage: splunk_query.py [options] splunk_host(s)
Run a splunk query using a python script (via the splunk SDK)
Copyright (c) 2013 Joseph Zeranski <madsc13ntist@gmail.com>

Options:
  -h, --help    show this help message and exit
  -u USER       the username to use to connect.
  -p PORT       the port to connect to. [8089]
  -o OUTFILE    a file to save results to.
  -a, --append  Append to OUTFILE instead of overwriting. (used with '-o')
  -s, --split   Split output into seperate files. (used with '-o')
  -U            prompt for username for each connection.
  -P            prompt for passwords for each connection.
  -q QUERY      The query to submit to splunk. (or a txt file)
  -i            drop to a python shell. (after connect(), before query)
  -I            drop to a python shell. (after each query)
~~~~
