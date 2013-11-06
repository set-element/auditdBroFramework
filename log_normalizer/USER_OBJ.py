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
data_filter = [ 'pid', 'time', 'node', 'ses', 'auid', 'type', 'egid', 'euid', 'fsgid', 'fsuid', 'gid', 'suid', 'sgid', 'uid', 'success', 'exit', 'terminal', 'exe']

class init:
    # common fields
    flavor = 'USER_OBJ'
    time = 1346257201.413
    node = 'localhost'
    # ses: The login session ID - maps user login to a process
    ses = -1
    # auid: audit user identity - remains the same through 
    #       user priv translations like su
    auid = -1
    # type: name of event type
    type = 'NULL'
    # 
    # who
    egid = -1
    euid = -1
    fsgid = -1
    fsuid = -1
    gid = -1
    suid = -1
    sgid = -1
    uid = -1
    pid = -1
    # success: Whether the system call succeeded or failed.
    success = 'NULL' 
    # exit: The exit value returned by the system call.
    exit = 0
    #
    term = 'NULL'
    exe = 'NULL'

    # take the record and normalize it against the local object type
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

            if key in data_filter:
                #print "key=" , key, " value=", value 
                if key == 'node':
                    s.node = urllib.quote(value) 
                elif key == 'ses': 
                    s.ses = value
                elif key == 'auid': 
                    s.auid = value
                elif key == 'type': 
                    s.type = value
                elif key == 'egid':
                    s.egid = value 
                elif key == 'euid': 
                    s.euid = value
                elif key == 'fsgid': 
                    s.fsgid = value
                elif key == 'fsuid': 
                    s.fsuid = value 
                elif key == 'gid': 
                    s.gid = value
                elif key == 'suid': 
                    s.suid = value
                elif key == 'sgid': 
                    s.sgid = value
                elif key == 'uid': 
                    s.uid = value
                elif key == 'pid':
                    s.pid = value
                elif key == 'success': 
                    s.success = value
                elif key == 'exit': 
                    s.exit = value
                elif key == 'terminal':
                    if value == '(none)':
                        s.term = 'NO_TERM'
                    else:
                        s.term = value
                elif key == 'exe':
                    s.exe = urllib.quote(value)

            if not au.next_field():
                break
       
        return s

    def print_o(s):
        # print the object in a well defined way
        print "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s" % (s.flavor, s.type, s.time, s.node, s.ses, s.auid, s.egid, s.euid, s.fsgid, s.fsuid, s.gid, s.suid, s.sgid, s.uid, s.pid, s.success, s.exit, s.term, s.exe)
