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
@load util

module AUDITD_POLICY;

export {

	redef enum Notice::Type += {
		AUDITD_PermissionTransform,
		AUDITD_SocketOpen,
		};

	# tag for file loaded
	const AUDITD_POLICY_LOAD = T;

	# List of identities which are consitered ok to be seen translating
	#  between one another.
	#
	global whitelist_to_id: set[string] &redef;
	global whitelist_from_id: set[string] &redef;

	### --- ###
	# This is the set of system calls that define the creation of a 
	#  network listening socket	
	global net_listen_syscalls: set[string] &redef;

	# Data struct to hold information about a generated socket
	type IPID: record {
		ip:      addr   &default=ADDR_CONV_ERROR;
		prt:     port   &default=PORT_CONV_ERROR;
		syscall: string &default=STRING_CONV_ERROR;
		#ts:	 time   &default=TIME_CONV_ERROR;
		error:   count  &default=0;
		};

	# this is a short term mapping designed to live for
	#   action duration
	global ip_id_map: table[string] of IPID;

	# this tracks rolling execution history of user and is
	#   keyed on the longer lived whoami id
	global execution_history: table[string] of set[string];

	global auditd_policy_dispatcher: event(i: Info);
	global s: event(s: string);

	## Execution configuration ##

	# blacklist of directories which 
	global exec_blacklist = /dev/ &redef;
	global exec_blacklist_test = T &redef;
	
	# identiy related configs
	global identity_drift_test = T &redef;


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

function get_identity_id(ses: int, node: string) : string
{
	# This function returns the identity-id (huh?!?)
	local ret = "NULL";
	
	if (! ((ses == INT_CONV_ERROR) || (node == STRING_CONV_ERROR)) )
		ret = fmt("%s%s", ses, node);

	return ret;
}


# This function compares two id values and in the event that
#  the post value are not whitelisted you get {0,1,2} 
#  depending on results.
function identity_atomic(old_id: string, new_id: string): bool
	{
	local ret_val = F;

	if ( (new_id != old_id) && (old_id != NULL_ID) ) {
		# there has been a non-trivial change in identity
		if ( (new_id !in whitelist_to_id) && (old_id !in whitelist_from_id) )
			ret_val = F;
		else
			ret_val = T;
		}

	return ret_val;
	}

# Look for a unexpected transformation of the identity subvalues
#  returning a vector of changes.
#
# NOTE: the record provided by identityState[] has *not* yet been synced 
#  to the current living record, so changes will be reflected in the diff
#  between the live record and the historical.
#
#function identity_test(ses: int, node: string, auid: string, uid: string, gid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string): count
function identity_test(inf: Info) : count
	{
	# return value is a map of 
	local ret_val = 0;

	# Tests current set of provided identities against the current archived set
	#  - pick it up.
	local id_index =  get_identity_id(inf$i$ses, inf$i$node);
	local old_id =  identityState[id_index];

	# In this case the record is either new or corrupt.
	if ( inf$i$uid == NULL_ID )
		return ret_val;

	# this is a mess, there *must* be a better way to do this ...
	if ( identity_atomic(old_id$uid, inf$i$uid)) {
		ret_val = ret_val + UID;
		print "diff UID";
		}

	if ( identity_atomic(old_id$gid, inf$i$gid)) {
		print "diff gid";
		ret_val = ret_val + GID;
		}
		
	if ( identity_atomic(old_id$euid, inf$i$euid)) {
		print "diff suid";
		ret_val = ret_val + EUID;
		}

	if ( identity_atomic(old_id$egid, inf$i$egid)) {
		print "diff egid";
		ret_val = ret_val + EGID;
		}

	if ( identity_atomic(old_id$suid, inf$i$suid)) {
		print "diff suid";
		ret_val = ret_val + SUID;
		}

	if ( identity_atomic(old_id$sgid, inf$i$sgid)) {
		print "diff sgid";
		ret_val = ret_val + SGID;
		}

	if ( identity_atomic(old_id$fsuid, inf$i$fsuid)) {
		print "diff fsuid";
		ret_val = ret_val + FSUID;
		}

	if ( identity_atomic(old_id$fsgid, inf$i$fsgid)) {
		print "diff sgid";
		ret_val = ret_val + FSGID;
		}

	if ( identity_atomic(old_id$auid, inf$i$auid)) {
		print "diff auid";
		ret_val = ret_val + AUID;
		}

	print fmt("ID check: %s", ret_val);
	return ret_val;
	}

function process_identity(i: Info) : count
	{
	local ret_val = 0;
	
	# run the change test and see what we can see
	local id_diff = identity_test(i);

	# look to see if anything has changed
	if ( id_diff > 0 ) {
		# global UID   = 1;
		# global GID   = 2;
		# global EUID  = 4;
		# global EGID  = 8;
		# global SUID  = 16;
		# global SGID  = 32;
		# global FSUID = 64;
		# global FSGID = 128;
		# global OGID  = 256;
		# global OUID  = 512;
		# global AUID  = 1024;
		
		


		}
	return ret_val;
	}

function network_log_listener(i: Info) : count
	{
	# This captures data from the system calls bind() and
	#  accept() and checks to see if the system in question already
	#  has an open network listener
	#
	# Here use the ip_id_map to store data: use {ses}{node} as the
	#   table index.  Results for the listener will be handed over to the 
	#   systems object for further analysis.

	local ret_val = 0;
	local temp_index = fmt("%s%s", i$ses, i$node);
	local t_IPID: IPID;

	# normally the syscall happens before the saddr data arrives
	#   will not assume that everything will get here in the order that
	#   would be most convieniant to us ...
	if ( temp_index in ip_id_map ) 
		t_IPID = ip_id_map[temp_index];

	#
	if ( t_IPID$error != 0 )
		return 1;

	if ( i$s_host != "NO_HOST" ) {
		local t_ip = to_addr(i$s_host);

		if ( t_ip != ADDR_CONV_ERROR )
			t_IPID$ip = t_ip;
		else 	# error
			++t_IPID$error;

		}

	if ( i$s_serv != "NO_PORT" ) {
		local t_port = s_port(i$s_serv);

		if ( t_port != PORT_CONV_ERROR )
			t_IPID$prt = t_port;
		else 	# error
			++t_IPID$error;

		}

	if ( i$syscall != "NO_SYSCALL" ) {

		if ( i$syscall in net_listen_syscalls )
			t_IPID$syscall = i$syscall;
		else 	# error
			++t_IPID$error;

		}

	# now if there is sufficient information in the t_IPID structure we
	#  have enjoyed it long enough and should pass it off to the server object
	#  holding all the info on this system
	#
	if ( (t_IPID$syscall != STRING_CONV_ERROR) && (t_IPID$ip != ADDR_CONV_ERROR)) {
		# process the new listener.
		#
		#event SERVER::holding();
		print fmt("NEW LISTEN SOCKET: %s", t_IPID$prt);
		}

	ip_id_map[temp_index] = t_IPID;	

	return t_IPID$error;
	}


function network_register_conn(i: Info) : count
	{
	# This attempts to register outbound network connection data with a central correlator
	#  in order to link the {user:conn} with the "real" netwok connection as seen by the 
	#  external network facing bro.
	#
	# Connect() calls look like:
	# 

	#if ( i$s_type == "inet" )
	#	print fmt("conn %s %s -> %s :%s", i$node, i$s_type, i$s_host, i$s_serv);

	return 0;
	}

function exec_pathcheck(exec_path: string) : count
	{
	# given a list of directory prefixes, check to see if the path
	#  sits in any of them
	# note that the path privided is should be consitered 'absolute'.

	local ret_val = 0;

	if ( exec_blacklist in exec_path ) {
		
		print fmt("EXECBLACKLIST: %s", exec_path);
		ret_val = 1;
		}
	return ret_val;
	}

function exec_wrapper(inf: Info) : count
	{
	# There are many things to be done with the execution chain.  This is the wrapper
	#   for that set of things to do.
	# Where is (it) being executed
	# Permissions chain/changes
	# Exec history ( n=5?)
	print "exec wrapper";
	local ret_val = 0;

	if ( exec_blacklist_test )
		exec_pathcheck(inf$exe);

	# track id drift.  start by just detecting it, then begin building
	#  whitelists and implement
	if ( identity_drift_test )	
		identity_test(inf);

	return ret_val;
	}

### ----- # ----- ###
#      Events
### ----- # ----- ###

event auditd_policy_dispatcher(inf: Info)
	{
	# This makes routing decisions for policy based on Info content.  It is
	#  a bit of a kluge, but will have to do for now.

	# Initial filtering based on action and key values
	#  ex: {PLACE_OBJ, PATH} .

	# Key is from audit.rules
	#
	local action = inf$action;
	local key    = inf$key;
	local syscall = inf$syscall;	

        switch ( action ) {
        case "EXECVE":
                break;
        case "GENERIC":
                break;
        case "PLACE":
                break;
        case "SADDR":
                break;
        case "SYSCALL":
		switch( syscall ) {
			### ----- ## ----- ####
			# from syscalls: bind, connect, accept, accept4, listen, socketpair, socket
			# key: SYS_NET
			case "connect":		# initiate a connection on a socket (C/S)
				network_register_conn(inf);
				break;
			case "bind": 		# bind a name/address to a socket (S)
				network_log_listener(inf);
				break;
			case "listen":		# listen for connections on a socket (S)
				network_log_listener(inf);
				break;
			case "socket":		# create an endpoint for communication (C/S)
				network_log_listener(inf);
				break;
			case "socketpair":	# create a pair of connected sockets (C/S)
				network_log_listener(inf);
				break;
			case "accept":		# accept a connection on a socket (S)
				network_log_listener(inf);
				break;
			case "accept4":		#  accept a connection on a socket (S)
				network_log_listener(inf);
				break;
			### ----- ## ----- ####
			# 
			case "execve":
				print "calling exec_wrapper";
				exec_wrapper(inf);
				break;
			}
                break;
        case "USER":
                break;
        }

	

	} # event end

# do a test for "where" somwthing is executed like /dev/shm ...


