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
data_filter = ['flavor', 'type', 'time', 'node', 'cwd', 'name', 'inode', 'mode', 'ouid', 'ogid']

class init:
    # common fields
    flavor = 'PLACE_OBJ'
    time = 1346257201.413
    type = 'NULL'
    node = 'localhost'
    #
    cwd = 'NULL'
    path_name = 'NULL'
    inode = -1
    mode = -1
    ouid = -1
    ogid = -1

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
                elif key == 'cwd':
                    s.cwd = urllib.quote(value)
                elif key == 'name':
                    s.path_name = urllib.quote(value)
                elif key == 'inode':
                    s.inode = value
                elif key == 'mode':
                    s.mode = value_raw
                elif key == 'ouid':
                    s.ouid = value
                elif key == 'ogid':
                    s.ogid = value

            if not au.next_field():
                break

        return s

    def print_o(s):
        print "%s %s %s %s %s %s %s %s %s %s" % (s.flavor, s.type, s.time, s.node, s.cwd, s.path_name, s.inode, s.mode, s.ouid, s.ogid)
