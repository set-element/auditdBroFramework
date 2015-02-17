Directory structure looks like:
bro_policy
  Former location of bro policy for digesting logs.  Moved to it's own repo for now.
  
docs
  Just some pics to keep track of the data flow.
  
log_normalizer
  Python script to take the output from the auditd logs and make them somewhat more machine parsable.
  
system_config
  Sample config files for the /etc/audit directory which will control the behavior of auditd (auditd.conf) and what will get recorded by the system reporting (audit.rules).
  

