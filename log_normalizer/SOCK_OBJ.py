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
data_filter = ['flavor', 'type', 'time', 'node', 'saddr']

class init:
    # common fields
    flavor = 'SADDR_OBJ'
    time = 1346257201.413
    type = 'NULL'
    node = 'localhost'
    #
    saddr = 'NULL'

    def load(s,au):
        
        event = au.get_timestamp()
        if event is None:
            print "Error getting timestamp - aborting"
            return 0

        s.time = "%d.%d" % (event.sec,event.milli)

        au.first_field()
        while True:
            key = au.get_field_name()
            value = au.interpret_field()
            value_raw = au.get_field_str()

            if key in data_filter:

                if key == 'node':
                    s.node = urllib.quote(value)
                if key == 'type':
                    s.type = urllib.quote(value)
                elif key == 'saddr':
                    s.saddr = urllib.quote(value)

            if not au.next_field():
                break

        return s

    def print_o(s):
        print "%s %s %s %s %s %s %s %s %s %s" % (s.flavor, s.type, s.time, s.node, s.cwd, s.path_name, s.inode, s.mode, s.ouid, s.ogid)
