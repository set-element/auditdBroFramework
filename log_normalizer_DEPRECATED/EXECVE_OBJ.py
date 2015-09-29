#!/usr/bin/env python

import os
import sys
import time
load_path = '../../bindings/python/build/lib.linux-i686-2.4'
import re
import auparse
import audit
import util
import urllib

# filter for object
data_filter = ['flavor', 'type', 'time', 'argc' ]
EXECVE_ARG_RE = re.compile('a[0-9]{1,3}')

class init:
    # common fields
    flavor = 'EXECVE_OBJ'
    time = 1346257201.413
    type = 'NULL'
    node = 'localhost'
    #
    argc = -1
    # aggrigate string holding the entire exec argument set
    arg = 'NULL'

    def load(s,au):
        
        event = au.get_timestamp()
        arg_count = 0

        if event is None:
            print "Error getting timestamp - aborting"
            return 0

        s.time = "%d.%d" % (event.sec,event.milli)

        au.first_field()
        while True:
            key = au.get_field_name()
            value = au.interpret_field()
            value_raw = au.get_field_str()

            if key == 'node':
                s.node = urllib.quote(value)
            if key == 'type':
                s.type = urllib.quote(value)
            elif key == 'argc':
                s.argc = value

            # add togther the collection of arguments into a
            #  single string, then encode it
            if EXECVE_ARG_RE.match(key) :
                if arg_count == 0:
                    s.arg = ''

                s.arg = "%s %s" % (s.arg,value)
                arg_count = arg_count + 1

                if arg_count == int(s.argc):
                    s.arg = urllib.quote(s.arg)

            if not au.next_field():
                break
        # some times if argc == -1 there is a bunch of kindof
        #  interesting, but not useful text.  snip it
        if s.argc == -1:
            s.arg = ''

        return s

    def print_o(s):
        print "%s %s %s %s %s %s %s %s %s %s" % (s.flavor, s.type, s.time, s.node, s.cwd, s.path_name, s.inode, s.mode, s.ouid, s.ogid)
