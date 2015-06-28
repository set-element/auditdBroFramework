#!/usr/bin/env python

import os
srcdir = os.getenv('srcdir')

# These define the two main points of configuration.
#  DATA_FILE: The constantly appending raw auditd log file
#  LOAD_PATH: Location of the audit-... install library files containing
#             the python2.6/site-packages
#
DATA_FILE = "/var/log/audit/audit.log"
#DATA_FILE = "./D"
LOAD_PATH = '/home/scottc/development/audit_watch/AUDIT2.2.2/lib64/python2.6/site-packages'

import sys
import time
import re

sys.path.insert(0, LOAD_PATH)
import auparse
import audit

# local python libs
from tail import FileTail
import USER_OBJ 
import PLACE_OBJ 
import SYSCALL_OBJ
import GENERIC_OBJ
import SOCK_OBJ
import EXECVE_OBJ

# Bunch of regular expressions to process the data raw data
# 
WHERE_RE= re.compile('CWD|PATH')
SYSCALL_RE = re.compile('SYSCALL')
WHO_RE = re.compile('USER_')
INTERNAL_RE = re.compile('DAEMON|SERVICE')
SOCKET_RE = re.compile('SOCKADDR')
EXECVE_RE = re.compile('EXECVE')

place_object = PLACE_OBJ.init()
user_object = USER_OBJ.init()
syscall_object = SYSCALL_OBJ.init()
socket_object = SOCK_OBJ.init()
execve_object = EXECVE_OBJ.init()
generic_object = GENERIC_OBJ.init()

event_count = 0
#
def none_to_null(s):
    'used so output matches C version'
    if s is None:
        return '(null)'
    else:
        return s

def feed_callback(au, cb_event_type, event_cnt):

    global event_count

    global place_object
    global user_object
    global syscall_object
    global socket_object
    global execve_object
    global generic_object

    while True:

        event_count += 1
        record_count = 1

        # Both the ses and pid values will be used for the base lookups in auditd_core.
        # Because of this, records after the first in an event will be benefited by passing
        #  this information along.  If this is not done, a great deal of state goo and churn
        #  is introduced later in the bro code.
        # The ses identifier is the primary with the pid as a backup since sid sometimes has
        #  a value of 'unset'.
        #
        ses_holder = 0
        pid_holder = 0
        event_rec_count = au.get_num_records()

        while True:
        
            if WHERE_RE.match(audit.audit_msg_type_to_name(au.get_type()) ) :
                place_object = place_object.load(au) 
                print "%s:%s:%s %s %s %s %s %s %s %s %s %s %s %s %s" % (event_count, event_rec_count, record_count, place_object.flavor, place_object.type, place_object.time, place_object.node, ses_holder, pid_holder, place_object.cwd, place_object.path_name, place_object.inode, place_object.mode, place_object.ouid, place_object.ogid)

            ### ------------------------------ ###
            elif WHO_RE.match(audit.audit_msg_type_to_name(au.get_type()) ) :
                user_object = user_object.load(au)
                if record_count == 1:
                    ses_holder = user_object.ses
                    pid_holder = user_object.pid
                else:
                    user_object.ses = ses_holder
                    user_object.pid = pid_holder

                print "%s:%s:%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s" % (event_count, event_rec_count, record_count, user_object.flavor, user_object.type, user_object.time, user_object.node, user_object.ses, user_object.auid, user_object.egid, user_object.euid, user_object.fsgid, user_object.fsuid, user_object.gid, user_object.suid, user_object.sgid, user_object.uid, user_object.pid, user_object.success, user_object.exit, user_object.term, user_object.exe)

            ### ------------------------------ ###
            elif SYSCALL_RE.match(audit.audit_msg_type_to_name(au.get_type()) ) :
                syscall_object = syscall_object.load(au)
                if record_count == 1:
                    ses_holder = syscall_object.ses
                    pid_holder = syscall_object.pid
                
                print '%s:%s:%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s' % (event_count, event_rec_count, record_count, syscall_object.flavor, syscall_object.type, syscall_object.time, syscall_object.node, syscall_object.ses, syscall_object.auid, syscall_object.syscall, syscall_object.key, syscall_object.comm, syscall_object.exe, syscall_object.a0, syscall_object.a1, syscall_object.a2, syscall_object.uid, syscall_object.gid, syscall_object.euid, syscall_object.egid, syscall_object.fsuid, syscall_object.fsgid, syscall_object.suid, syscall_object.sgid, syscall_object.pid, syscall_object.ppid, syscall_object.tty, syscall_object.success, syscall_object.exit)

            ### ------------------------------ ###
            elif SOCKET_RE.match(audit.audit_msg_type_to_name(au.get_type()) ) :
                socket_object = socket_object.load(au)
                print '%s:%s:%s %s %s %s %s %s %s %s' % (event_count, event_rec_count, record_count, socket_object.flavor, socket_object.type, socket_object.time, socket_object.node, ses_holder, pid_holder, socket_object.saddr) 

            ### ------------------------------ ###
            elif EXECVE_RE.match(audit.audit_msg_type_to_name(au.get_type()) ) :
                execve_object = execve_object.load(au)
                print '%s:%s:%s %s %s %s %s %s %s %s %s' % (event_count, event_rec_count, record_count, execve_object.flavor, execve_object.type, execve_object.time, execve_object.node, ses_holder, pid_holder, execve_object.argc, execve_object.arg)

            ### ------------------------------ ###
            else:
                generic_object = generic_object.load(au)
                if record_count == 1:
                    ses_holder = generic_object.ses
                    pid_holder = generic_object.pid
                else:
                    generic_object.ses = ses_holder
                    generic_object.pid = pid_holder

                print '%s:%s:%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s' % (event_count, event_rec_count, record_count, generic_object.flavor, generic_object.type, generic_object.time, generic_object.node, generic_object.ses, generic_object.auid, generic_object.key, generic_object.comm, generic_object.exe, generic_object.a0, generic_object.a1, generic_object.a2, generic_object.uid, generic_object.gid, generic_object.euid, generic_object.egid, generic_object.fsuid, generic_object.fsgid, generic_object.suid, generic_object.sgid, pid_holder, generic_object.ppid, ses_holder, generic_object.tty, generic_object.terminal, generic_object.success, generic_object.exit)

            record_count += 1

            if not au.next_record(): break
        if not au.parse_next_event(): break

######################################################
# this is the main "loop"
######################################################
au = auparse.AuParser(auparse.AUSOURCE_FEED);
event_cnt = 1
au.add_callback(feed_callback, [event_cnt])
chunk_len = 3

t=FileTail(DATA_FILE)
for s in t:
    s_len = len(s)
    beg = 0
    while beg < s_len:
        end = min(s_len, beg + chunk_len)
        data = s[beg:end]
        beg += chunk_len
        au.feed(data)

au.flush_feed()

sys.exit(0)

