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
data_filter = [ 'node', 'msg', 'auid', 'egid', 'euid', 'fsgid', 'fsuid', 'gid', 'suid', 'sgid', 'uid', 'comm', 'exe', 'pid', 'ppid', 'cwd', 'key', 'tty', 'terminal', 'saddr', 'type', 'ses', 'auid', 'exit', 'success', 'a0', 'a1', 'a2' ]


class init:
    # common fields
    flavor = 'GENERIC_OBJ'
    time = 1346257201.413
    node = 'localhost'
    # All events that are logged from one application's system call have the same event ID
    #syscall_id = 0
    # ses: The login session ID - maps user login to a process
    ses = -1
    # auid: audit user identity - remains the same through user priv translations like su
    auid = -1 
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
    ##  process info
    # comm: The application name under which it appears in the task list. 
    comm = 'NULL'
    # exe: The resolved pathname to the binary program.
    exe = 'NULL' 
    a0 = 'NULL'
    a1 = 'NULL'
    a2 = 'NULL'
    pid = -1
    ppid = -1
    # success: Whether the system call succeeded or failed.
    success = 'NULL' 
    # exit: The exit value returned by the system call.
    exit = 0
    key = 'NULL'
    tty = 'NULL'
    terminal = 'NULL'
    #saddr = "NULL"

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
                elif key == 'node':
                    s.node = urllib.quote(value)
                elif key == 'msg':
                    s.msg = urllib.quote(value)
                elif key == 'auid':
                    s.auid = value_raw
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
                elif key == 'comm':
                    s.comm = urllib.quote(value)
                elif key == 'exe':
                    s.exe = urllib.quote(value)
                elif key == 'pid':
                    s.pid = value_raw
                elif key == 'ppid':
                    s.ppid = value_raw
                elif key == 'key':
                    s.key = value
                elif key == 'tty':
                    if value == '(none)':
                        s.tty = 'NO_TTY'
                    else:
                        s.tty = value
                elif key == 'terminal':
                    if value == '(none)':
                        s.terminal = 'NO_TERMINAL'
                    else:
                        s.terminal = value
                elif key == 'saddr':
                    s.saddr = value
                elif key == 'type':
                    s.type = value
                elif key == 'ses':
                    s.ses = value_raw
                elif key == 'auid':
                    s.auid = value_raw
                elif key == 'exit':
                    s.exit = urllib.quote(value)
                elif key == 'success':
                    s.success = value
                elif key == 'a0':
                    s.a0 = urllib.quote(value_raw)
                elif key == 'a1':
                    s.a1 = urllib.quote(value_raw)
                elif key == 'a2':
                    s.a2 = urllib.quote(value_raw)

            if not au.next_field():
                break

        return s
                
