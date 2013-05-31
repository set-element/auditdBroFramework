#!/usr/bin/env python

import urllib
import syslog
import time
import socket
import re
import pwd
import grp
import shlex
import binascii

def process_string(value):
    # this will return the translated value unless (1) a binary value 
    #   is returned as part of the translation, or (2) a ValueError is
    #   thrown which typically indicates that a "normal" string has been
    #   handed to the function

    retstring = ''

    # too short - just return value
    if len(value) <= 2:
        return value

    for i in range(len(value)/2):
        realIdx = i*2

        # ValueError happens w/ 'normal' text - if it
        #  is run into, just return value
        try:
            n = int(value[realIdx:realIdx+2],16)
        except ValueError:
            return value

        if ( n > 31 and n < 127 ):
            retstring = retstring + chr(n)
        else:
            # the character is non-printing so just return value
            return value

    return retstring

def process_exe(value):
    ret = 'ERROR'

    if len(value) % 2 != 0:
        value = value + '0'

    try:
        ret = binascii.unhexlify(value)
        #print ret
    except TypeError:
        ret = value

    return ret



