#!/usr/bin/env python

__version__    = "0.0.1"
__date__       = "02.22.2013"
__author__     = "Joseph Zeranski"
__maintainer__ = "Joseph Zeranski"
__email__      = "madsc13ntist gmail.com"
__copyright__  = "Copyright 2013, " + __author__
__license__    = "MIT"
__status__     = "Prototype"
__credits__    = [""]
__description__= "Run a splunk query using a python script (via the splunk SDK)"

####################### MIT License ####################### 
# Copyright (c) 2013 Joseph Zeranski
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
###########################################################

### Import Modules
import os
import re
import sys
import code
import getpass
import optparse
import platform
import datetime
from time import sleep
from splunklib.binding import HTTPError
import splunklib.client as client

### Regex used to recognize flags and their associated values
flags_re = re.compile("--(\w+)=(.+?)\s")

splunk_create_flags = [
    "auto_cancel",\
    "auto_finalize_ec",\
    "auto_pause",\
    "earliest_time",\
    "enable_lookups",\
    "exec_mode",\
    "id",\
    "latest_time",\
    "max_count",\
    "max_time",\
    "now",\
    "reduce_freq",\
    "reload_macros",\
    "required_field_list",\
    "rf",\
    "rt_blocking",\
    "rt_indexfilter",\
    "rt_maxblocksecs",\
    "rt_queue_size",\
    "search_mode",\
    "spawn_process",\
    "status_buckets",\
    "time_format",\
    "timeout",\
]

splunk_results_flags = [
    "count",\
    "f",\
    "field_list",\
    "offset",\
    "output_mode",\
    "search",\
]

### Define constants
os_type = platform.system()
leaveshell = "Ctrl+D"
rcpath = "~/.splunkrc"
if "Windows" in os_type:
    rcpath = os.environ["USERPROFILE"] + os.sep + ".splunkrc"
    leaveshell = "Ctrl+Z"
interactive_shell_prompt = "Type '%s' to close shell. ('Type exit()' to close the script completely.)" % (leaveshell)

### Define Functions
def ConnectToSplunk(splunk_host, port, user, passwd, **kwargs):
    """
    Make the connection to the splunk search-head
    """
    print("Connecting to: %s:%d" % (splunk_host, port))
    service = client.connect(host=str(splunk_host), port=int(port), username=str(user), password=str(passwd), **kwargs)
    return service

def QueryIsValid(splunk_connection_handle, query):
    try:
        splunk_connection_handle.parse(query, parse_only=True)
        return True
    except HTTPError as e:
        print("query '%s' is invalid:\n\t%s" % (query, e.message), 2)
        return False

def ParseQuery(query):
    """
    Take a raw query, seperate flags/values from the query and return both seperately.  (str, dict)
    """
    ### parse out flags
    flag_dict = {}
    flags = flags_re.findall(query)
    if flags:
        flags = [ x for x in flags if x not in [None] ]
        for flag, value in flags:
            flag_dict[flag] = value.lstrip("'").rstrip("'").lstrip('"').rstrip('"')

    ###remove flags and values from raw_query
    for flag, value in flag_dict.items():
        query = re.sub("--"+flag+"=(\"|')?"+value+"(\"|')?", "", query)

    return (query, flag_dict)

def SubmitQuery(splunk_connection_handle, query, **flag_dict):
    """
    Submit a query to splunk and return the results
    """
    create_flags = {}
    results_flags = {}

    if flag_dict:
        for flag, value in flag_dict.items():
            if flag in splunk_create_flags:
                create_flags[flag] = value
            elif flag in splunk_results_flags:
                results_flags[flag] = value

    try:
        splunk_connection_handle.parse(query, parse_only=True)
    except HTTPError as e:
        cmdopts.error("query '%s' is invalid:\n\t%s" % (query, e.message), 2)
        return False

    job = service.jobs.create(query, **create_flags)

    while True:
        job.refresh()
        stats = {'isDone': job['isDone'],
                 'doneProgress': job['doneProgress'],
                 'scanCount': job['scanCount'],
                 'eventCount': job['eventCount'],
                 'resultCount': job['resultCount']}
        progress = float(stats['doneProgress'])*100
        scanned = int(stats['scanCount'])
        matched = int(stats['eventCount'])
        results = int(stats['resultCount'])

        if stats['isDone'] == '1':
            break
        sleep(2)

    if not results_flags.has_key('count'): results_flags['count'] = 0
    job_results = job.results(**results_flags)
    result = ""
    while True:
        content = job_results.read(1024)
        if len(content) == 0: break
        result += content
    job.cancel()

    return result


### If the script is being executed (not imported).
if __name__ == "__main__":
    opt_parser = optparse.OptionParser()
    opt_parser.usage  = "%prog [options] splunk_host(s)\n"

    #''' Additional formatting for Meta-data ''''''''''''''''''
    if __description__ not in ["", [""], None, False]:
        opt_parser.usage += __description__ + "\n"
    opt_parser.usage += "Copyright (c) 2013 " + __author__ + " <" + __email__ + ">"
    if __credits__ not in ["", [""], None, False]:
        opt_parser.usage += "\nThanks go out to "
        if type(__credits__) == str:
            opt_parser.usage += __credits__ + "."
        elif type(__credits__) == list:
            if len(__credits__) == 1:
                opt_parser.usage += __credits__[0] + "."
            else:
                opt_parser.usage += ', '.join(__credits__[:-1]) + " and " + __credits__[-1] + "."
    #'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

    # Add Param Option
    opt_parser.add_option("-u",
                          dest="user",
                          action  = "store",
                          default = getpass.getuser(),
                          help    = "the username to use to connect.")
    opt_parser.add_option("-p",
                          dest="port",
                          action  = "store",
                          default = 8089,
                          help    = "the port to connect to. [8089]")
    opt_parser.add_option("-o",
                          dest="outfile",
                          action  = "store",
                          default = False,
                          help    = "a file to save results to.")
    opt_parser.add_option("-a", "--append",
                          dest="appfile",
                          action  = "store_true",
                          default = False,
                          help    = "Append to OUTFILE instead of overwriting. (used with '-o')")
    opt_parser.add_option("-s", "--split",
                          dest="splitoutput",
                          action  = "store_true",
                          default = False,
                          help    = "Split output into seperate files. (used with '-o')")
    opt_parser.add_option("-U",
                          dest    = "askuser",
                          action  = "store_true",
                          default = False,
                          help    = "prompt for username for each connection.")
    opt_parser.add_option("-P",
                          dest    = "askpass",
                          action  = "store_true",
                          default = False,
                          help    = "prompt for passwords for each connection.")
    opt_parser.add_option("-q",
                          dest="query",
                          action  = "store",
                          default = False,
                          help    = "The query to submit to splunk. (or a txt file)")
    opt_parser.add_option("-i",
                          dest    = "interact_before_query",
                          action  = "store_true",
                          default = False,
                          help    = "drop to a python shell. (after connect(), before query)")
    opt_parser.add_option("-I",
                          dest    = "interact_after_query",
                          action  = "store_true",
                          default = False,
                          help    = "drop to a python shell. (after each query)")


    # Parse options and args
    (options, args) = opt_parser.parse_args()

    # Do things with your options and args.
    if not args:
        opt_parser.print_help()	# Print usage info
        exit(1)

    ### Identify queries
    queries = []
    if os.path.isfile(options.query):
        with open(options.query, 'r') as f:
            for query in f.readlines():
                query = query.rstrip()
                if not query.startswith("#") and len(query) > 1:
                    queries.append(ParseQuery(query))
    else:
        queries = [ParseQuery(options.query)]

    passwd = str(getpass.getpass())
    options.port = int(options.port)
    out_mode = "w"
    if options.appfile:
        out_mode = "a"

    for splunk_host in args:
        if options.askuser:
            user = raw_input("Username: ")
        if options.askpass:
            passwd = getpass.getpass()

        ### Create the connection
        service = ConnectToSplunk(splunk_host, options.port, options.user, passwd)

        ### Start submitting these queries
        q_count = -1
        for query, flags in queries:
            if options.interact_before_query:
                code.interact(interactive_shell_prompt, local=locals())

            if QueryIsValid(service, query):
                print("Started: %s" % (datetime.datetime.now()))
                print("Query: %s" % (query))
                if flags:
                    print("Flags:")
                    for flag, value in flags.items():
                        print("\t%s=%s" % (flag, value))

                output = SubmitQuery(service, query, **flags)
                print("Results:\n%s" % (output))
                print("Finished: %s" % (datetime.datetime.now()))

                if output:
                    if options.outfile:
                        if options.splitoutput:
                            q_count += 1
                            with open(options.outfile + '.' + str(q_count), out_mode) as outfile:
                                outfile.write(output)
                        else:
                            with open(options.outfile, out_mode) as outfile:
                                outfile.write(output)

            if options.interact_after_query:
                code.interact(interactive_shell_prompt, local=locals())

