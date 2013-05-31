# auditd_policy.bro
# Scott Campbell
#
# 
# Every login and related activities is associated with login session id (ses)
#   and the {pid} pair.  This collection of stuff identifies the key which
#   is actually the table used to hold multi action/record data.
#
# The ses id is monotomicly incrementing, so the odds of collision between many
#   systems is reasonably high.  Because of this the node identity is appended to 
#   ses and pid values since the internal systems should remove duplicate values.
#
@load auditd_core
@load util

module AUDITD_POLICY;

export {

	redef enum Notice::Type += {
		AUDITD_PermissionTransform,
		};

	global whitelist_to_id: set[string] &redef;
	global whitelist_from_id: set[string] &redef;

	### --- ###
	# This is the set of system calls that define the creation of a 
	#  network listening socket	
	global net_listen_syscalls: set[string];

	type IPID: record {
		ip:      addr &default=ADDR_CONV_ERROR;
		prt:     count &default=PORT_CONV_ERROR;
		syscall: string &default=STRING_CONV_ERROR;
		error:   count &default=0;
		}

	# this is a short term mapping designed to live for
	#   action duration
	ip_id_map: table[string] if IPID;

	# this tracks rolling execution history of user and is
	#   keyed on the longer lived whoami id
	execution_history: table[string] of set[string];

	} # end export
		
### ----- # ----- ###
#      Local Constants
### ----- # ----- ###
global NULL_ID: string = "-1";

global UID   = 1;
global GID   = 2;
global EUID  = 4;
global EGID  = 8;
global SUID  = 16;
global SGID  = 32;
global FSUID = 64;
global FSGID = 128;
global OGID  = 256;
global OUID  = 512;
global AUID  = 1024;


### ----- # ----- ###
#      Config
### ----- # ----- ###
redef net_listen_syscalls += { "bind", "accept", };

### ----- # ----- ###
#      Functions
### ----- # ----- ###

function identity_atomic(old_id: string, new_id: string): count 
	{
	local ret_val = 0;

	if ( (new_id != old_id) && (old_id != NULL_ID) ) {
		# there has been a non-trivial change
		if ( (new_id !in whitelist_to_id) && (old_id !in whitelist_from_id) )
			ret_val = 1;
		else
			ret_val = 2;
		}

	return ret_val;
	}

function identity_test(whoami, auid: int, uid: int, gid: int, euid: int, egid: int, fsuid: int, fsgid: int, suid: int, sgid: int): count
	{
	# return value is a map of 
	local ret_val = 0;

	# Tests current set of provided identities against the current archived set
	#
	local t_Info = AUDITD_CORE::get_record(index,pid,ses,node);

	# In this case the record is either new or corrupt.
	if ( t_Info$uid == NULL_ID )
		return;

	# this is a mess, there *must* be a better way to do this ...
	if ( identity_atomic(t_Info$uid, uid) == 1 )
		ret_val = ret_val || UID;

	if ( identity_atomic(t_Info$gid, gid) == 1 )
		ret_val = ret_val || GID;
		
	if ( identity_atomic(t_Info$euid, euid) == 1 )
		ret_val = ret_val || EUID;

	if ( identity_atomic(t_Info$egid, egid) == 1 )
		ret_val = ret_val || EGID;

	if ( identity_atomic(t_Info$suid, suid) == 1 )
		ret_val = ret_val || SUID;

	if ( identity_atomic(t_Info$sgid, sgid) == 1 )
		ret_val = ret_val || SGID;

	if ( identity_atomic(t_Info$fsuid, fsuid) == 1 )
		ret_val = ret_val || FSUID;

	if ( identity_atomic(t_Info$fsgid, fsgid) == 1 )
		ret_val = ret_val || FSGID;

	if ( identity_atomic(t_Info$ouid, ouid) == 1 )
		ret_val = ret_val || OUID;

	if ( identity_atomic(t_Info$ogid, ogid) == 1 )
		ret_val = ret_val || OGID;

	if ( identity_atomic(t_Info$auid, auid) == 1 )
		ret_val = ret_val || AUID;

	return ret_val;
	}


function network_log_listener(index: string, whoami: string, s_host: string, s_serv: string, syscall: string) : count
	{
	# This captures data from the system calls bind() and
	#  accept() and checks to see if the system in question already
	#  has an open network listener
	#
	# Here use the ip_id_map to store data: use {index}{whoami} as the
	#   table index.  Results for the listener will be handed over to the 
	#   systems object for further analysis.
	local ret_val = 0;
	local temp_index = fmt("%s%s", index, whoami);
	local t_IPID: IPID;

	# normally the syscall happens before the saddr data arrives
	#   will not assume that everything will get here in the order that
	#   would be most convieniant to us ...
	if ( temp_index in ip_id_map ) 
		t_IPID = ip_id_map[temp_index];

	#
	if ( t_IPID$error != 0 )
		return 1;

	if ( s_host != "NO_HOST" ) {
		local t_ip = s_addr(s_host);

		if ( t_ip != ADDR_CONV_ERROR )
			t_IPID$ip = t_ip;
		else 	# error
			++t_IPID$error;

		}

	if ( s_serv != "NO_PORT" ) {
		local t_port = s_port(s_serv);

		if ( t_port != PORT_CONV_ERROR )
			t_IPID$prt = t_port;
		else 	# error
			++t_IPID$error;

		}

	if ( syscall != "NO_SYSCALL" ) {

		if ( syscall in net_listen_syscalls )
			t_IPID$syscall = syscall;
		else 	# error
			++t_IPID$error;

		}

	# now if there is sufficient information in the t_IPID structure we
	#  have enjoyed it long enough and should pass it off to the server object
	#  holding all the info on this system
	#
	if ( (t_IPID$syscall != STRING_CONV_ERROR) && (t_IPID$ip != ADDR_CONV_ERROR)) {
		event SERVER::holding();
		}

	ip_id_map[temp_index] = t_IPID;	

	return t_IPID$error;
	}


function network_register_conn



### ----- # ----- ###
#      Events
### ----- # ----- ###
event auditd_execve(index: string, action: string, ts: time, node: string, ses: int, pid: int, argc: int, argument: string) &priority=5
	{
	# look up the related record
	local t_Info = get_record(index,pid,ses,node);


	}


event auditd_generic(index: string, action: string, ts: time, node: string, ses: int, pid: int, auid: string, comm: string, exe: string, a0: string, a1: string, a2: string, uid: string, gid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string, ppid: int, tty: string, terminal: string, success: string, ext: string) &priority=5
	{
	# look up the related record
	local t_Info = get_record(index,pid,ses,node);


	}

event auditd_place(index: string, action: string, ts: time, node: string, ses: int, pid: int, cwd: string, path_name: string, inode: int, mode: int, ouid: string, ogid: string) &priority=5
	{
	# look up the related record
	local t_Info = get_record(index,pid,ses,node);


	}

event auditd_saddr(index: string, action: string, ts: time, node: string, ses: int, pid: int, saddr: string) &priority=5
	{

	# most of the work here will be in decoding the saddr structure
	#
	# common types:
	# 	inet host 1.2.3.4 serv:123
	# 	local /dev/filename
	# 	netlink /dev/log
	#
	# will be broken out into the followign structures
	#
	# 	type : {inet host|local|netlink}
	# 	host : {file|device|ip} identifies where
	# 	serv : {port} (optional) identifies what
	#
	
	local t_Info = get_record(index,pid,ses,node);

	# decode the saddr structure
	local t_saddr = unescape_URI(saddr);
	local split_saddr = split(t_saddr, / / );

	local stype = split_saddr[1];
	local host = split_saddr[2];

	if ( |split_saddr| > 2 ) {
		local serv = split_saddr[3];
		local t_serv = split( serv, /:/ );
		}

	local t_host = split( host, /:/ );

	# make decisions based on field 1
	if ( stype == "inet" ) {

		t_Info$s_type = stype;
		t_Info$s_host = t_host[2];
		t_Info$s_serv = t_serv[2];

		}
	else if ( stype == "local" ) {
		
		t_Info$s_type = stype;
		t_Info$s_host = host;

		} 
	else if ( stype == "netlink" ) {

		t_Info$s_type = stype;
		t_Info$s_host = t_host[2];
		
		}

	update_value(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 )
		Log::write(LOG, t_Info);
	}


event auditd_syscall(index: string, action: string, ts: time, node: string, ses: int, pid: int, auid: string, syscall: string, key: string, comm: string, exe: string, a0: string, a1: string, a2: string, uid: string, gid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string, ppid: int, tty: string, success: string, ext: string)  &priority=5
	{
	# look up the related record
	local t_Info = get_record(index,pid,ses,node);

	}

event auditd_user(index: string, action: string, ts: time, node: string, ses: int, pid: int, auid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string, uid: string, gid: string, exe: string, terminal: string, success: string, ext: string, msg: string) &priority=5
	{
	# look up the related record
	local t_Info = get_record(index,pid,ses,node);

	}
	

event bro_init() &priority = 5
{
	  Log::create_stream(AUDITD_CORE::LOG, [$columns=Info]);
}
