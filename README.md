Directory structure looks like:
bro_policy
  Former location of bro policy for digesting logs.  Moved to it's own repo for now.
  
docs
  Just some pics to keep track of the data flow.
  
log_normalizer
  c-Based log normalizer script - see README for details.  More docs coming...

log_normalizer_deprecated
  Python script to take the output from the auditd logs and make them somewhat more machine parsable.  Please note that this program leaks memory badly based on some interactions between python < 3.3 and libc.  Since the audit-libs-python.x86_64 package seems to have issues with python 3.x I have given up hope for this.
  
system_config
  Sample config files for the /etc/audit directory which will control the behavior of auditd (auditd.conf) and what will get recorded by the system reporting (audit.rules).
  

