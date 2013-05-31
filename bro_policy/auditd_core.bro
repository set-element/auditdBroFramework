# auditd_core.bro
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

module AUDITD_CORE;

export {

	# AUDITD_CORE log stream identifier
	redef enum Log::ID += { LOG };

	const id_default = "-1";
	const info_null  = "NULL";

	# Used to keep track of the assigned *id/*gid values for a per host session identity.
	#   This is the description of the who in an auditable event.  It needs to be stored
	#   separately from the Info record since it lives for the entire duration of the session
	#   rather than the individual event.
	#
	# It is logged as a component of the Info record, and updated at a:b:1 for the primary
	#   / alpha record.
	#
	type identity: record {
		ses:       int &default=-1;             # numeric session id or 'unset'
		node:   string &default="NULL";         # what host is this happening on
		whoami: string &default="NULL";         # index that this record is stored under
		## -- identity info (process) --
		auid:   string &default=s_default;	# audit id, immutable even if id changes
		uid:    string &default=s_default;	# user id
		gid:    string &default=s_default;	# group id
		euid:   string &default=s_default;	# effective user id
		egid:   string &default=s_default;	# effective group id
		suid:   string &default=s_default;	# set user id
		sgid:   string &default=s_default;	# set group id
		## -- identity info (file system) --
		fsuid:  string &default=s_default;	# file system user id
		fsgid:  string &default=s_default;	# file system group id
		};
	

	# Track action characteristics - this is defined as the aggrigate characteristics of
	#   an individual auditable event not defined in the identity object.  This is the description
	#   of what happened rather than who did it.
	#
	type Info: record {
		## -- indexing information --
		ts:        time   &log;				#
		i:         identity &log;			# identity structure defined above
		id:        string &log &default=info_null;	# identifier provided by key in getid()
		pid:       int    &log &default=-1;		# curent pid

		## -- class info --
		action:    string &log &default=info_null;	# class of action (ex: 'SYSCALL_OBJ'), also ERROR_FLAG
		key:       string &log &default=info_null;	# subtype of class (ex: 'SYS_NET')

		## -- what happened --
		syscall:   string &log &default=info_null;	# syscall name
		comm:      string &log &default=info_null;	# name as appears in 'ps'
		exe:       string &log &default=info_null;	# full exe name + path

		## -- details --
		msg:       string &log &default=info_null;
		s_type:    string &log &default=info_null;	# name or file type socket
		s_host:    string &log &default=info_null;	# *where* the socket type is pointing
		s_serv:    string &log &default=info_null;	# service it is pointing to
		path_name: string &log &default=info_null;	# gen 1x per path element passed to syscall
		cwd:       string &log &default=info_null;	# current working direct at time of syscall
		a0:        string &log &default=info_null;	# argument0 to syscall
		a1:        string &log &default=info_null;	# ..
		a2:        string &log &default=info_null;	# ..
		arg_t:     string &log &default=info_null;	# for exec, *total* set of args
		ppid:      int    &log &default=-1; 		# parent pid
		tty:       string &log &default=info_null; 	# tty type or NO_TTY
		terminal:  string &log &default=info_null; 	# terminal data or NO_TERM
		success:   string &log &default=info_null;	# if syscall succedded or not 
		ext:       string &log &default=info_null;	# exit code for call
		ouid:      string &log &default=info_null;	# uid on file system inode
		ogid:      string &log &default=info_null;	# gid on file system inode
		};

	const zero_int: int = 0;	

	# to map identity <=> action use sid:node as "identity-id"
	# to map action-id and record[n] use index:node as "action-id"

	# main state table: driven by *key*
	global actionState: table[string] of Info;
	global identityState: table[string] of identity;	

	# exported functions
	global get_action_id: function(index: string, node: string) : string;
	global getrecord: function(index: string, pid: int, ses: int, node: string) : Info;
	global last_record: function(index: string): count;
	global update_value: function(i: Info);

	}

### ----- # ----- ###
#      Functions
### ----- # ----- ###

function get_action_id(index: string, node: string) : string
{
	# This function returnes the action-id ( index_major:node )
	# In the event of the index value not being of the expected form
	#   the function returns "NULL" rather than an indeterminant quantity.
	#

	# This function should never return this value.
	local ret = "NULL";

	# take index value (a:b:c) and split it up
	local i = split(index, /:/);

	# weed out corrupt data
	if ( |i| == 3 ) {

		local i_major = to_count(i[1]);
		ret = fmt("%s%s", i_major, node);

		}

	return ret;

} # function get_action_id end

function get_identity_id(ses: int, node: string) : string
{
	# This function returns the identity-id (huh?!?)
	local ret = "NULL";
	
	if (! ((ses == INT_CONV_ERROR) || (node == STRING_CONV_ERROR)) )
		ret = fmt("%s%s", ses, node);

	return ret;
}


function get_action_obj(index: string, node: string) : Info
{
	local key = get_action_id(index,node);
	local t_Info: Info;

	# error state test - the action 
	if ( key == "NULL" ) {
		t_Info$action = "ERROR_STATE";
		return t_Info;
		}

	# If the key is been registered use it, else
	#  use t_Info.
	if ( key in actionState ) {
		t_Info = actionState[key];
		}
	else {
		# add the key instance
		t_Info$node = node;
		actionState[key] = t_Info;
		}

	return t_Info;

} # end get_action_obj

function get_identity_obj(ses: int, node: string) : identity
{
	local key = get_identity_id(ses, node);
	local t_identity: identity;

	if ( key in identityState )	
		t_identity = identityState[key];
	
	return t_identity;
} # end get_identity_obj

function last_record(index: string): count
{
	# test the index field to see if this is the last record in a series
	#  3:2:2 means index:total_records:record_index
	# so in this case the result would be true
	#
	local ret = 0;
	local index_split = split(index, /:/);

	if ( index_split[2] == index_split[3] )
		ret = 1;
	return ret;
}

function update_action(i: Info)
{
	# Update the indexed Info obj with the provided t_Info
	local key = get_action_id(i$index,i$node);
	# update the record value
	if ( key in actionState ) {

		actionState[key] = i;
		}
	else {
		print fmt("UPDATE ERROR for index %s", key);
		}
}

function sync_identity(index: string, node: string)
{
	# Take identity and sync it with the action structure
	local t_Info = get_action_obj(index,node);
	local t_identity = get_identity_obj(t_Info$ses, t_Info$node);

	t_Info$i = t_identity;

	local key = get_action_id(t_Info$index,t_Info$node);
	actionState[key] = t_Info;		
}

function delete_action(index: string, node: string)
{
	# remove action obj
	local key = get_action_id(index,node);

	if ( key in actionState )
		delete actionState[key];
}

function update_identity(ses: int, node: string, auid: string, uid: string, gid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string) : count
{
	# Update values for the identity object.  If the obj is not in the
	#   identityState table, create it
	local key = get_identity_id(ses, node);
	local t_identity: identity;

	if ( key == "NULL" )
		return 2;

	if ( key in identityState )
		t_identity = identityState[key];

	# now update the values
	if ( auid != STRING_CONV_ERROR )
		t_identity$auid = auid;

	if (  uid != STRING_CONV_ERROR )
		t_identity$uid = uid;

	if ( gid != STRING_CONV_ERROR )
		t_identity$gid = gid;

	if ( euid != STRING_CONV_ERROR )
		t_identity$euid = euid;

	if ( egid != STRING_CONV_ERROR )
		t_identity$egid = egid;

	if ( fsuid != STRING_CONV_ERROR )
		t_identity$fsuid = fsuid;

	if ( fsgid != STRING_CONV_ERROR )
		t_identity$fsgid = fsgid;

	if ( suid != STRING_CONV_ERROR )
		t_identity$suid = suid;

	if ( sgid != STRING_CONV_ERROR )
		t_identity$sgid = sgid;

	identityState[key] = t_identity;

	return 0;
} # end update_identity


### ----- # ----- ###
#      Events
### ----- # ----- ###
event auditd_execve(index: string, action: string, ts: time, node: string, ses: int, pid: int, argc: int, argument: string)
	{
	# Beta event
	# look up the related record
	local t_Info = get_action_obj(index,node);
	local error_count = 0;

	# for now just update the field values
	# only update the action for some types
	
	if ( action == STRING_CONV_ERROR ) 
		++error_count;
	else
		t_Info$action = action;
	
	if ( ts == TIME_CONV_ERROR )
		++error_count;
	else
		t_Info$ts = ts;
	
	if ( ses == INT_CONV_ERROR )
		++error_count;
	else
		t_Info$ses = ses;

	if ( pid == INT_CONV_ERROR )
		++error_count;
	else	
		t_Info$pid = pid;
	
	if ( argument == STRING_CONV_ERROR )
		++error_count;
	else
		t_Info$arg_t = argument;

	update_action(t_Info);

	# if the last record, print it and clean up the action state
	if ( last_record(index) == 1 ) {
		t_Info = sync_identity(index,node, t_Info);
		Log::write(LOG, t_Info);
		delete_action(index,node);
		}

	} # end auditd_execve


event auditd_generic(index: string, action: string, ts: time, node: string, ses: int, pid: int, auid: string, comm: string, exe: string, a0: string, a1: string, a2: string, uid: string, gid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string, ppid: int, tty: string, terminal: string, success: string, ext: string)
	{
	# Alpha event
	# look up the related record
	local t_Info = get_info_record(index,node);

	# for now just update the field values
	# only update the action for some types
	t_Info$action = action;
	t_Info$ts = ts;
	t_Info$ses = ses;
	t_Info$pid = pid;
	#
	t_Info$comm = comm;
	t_Info$exe = exe;
	t_Info$a0 = a0;
	t_Info$a1 = a1;
	t_Info$a2 = a2;
	t_Info$ppid = ppid;
	t_Info$tty = tty;
	t_Info$terminal = terminal;
	t_Info$success = success;
	t_Info$ext = ext;
	# identification
	t_Info$uid = uid;
	t_Info$gid = gid;
	t_Info$auid = auid;
	t_Info$euid = euid;
	t_Info$egid = egid;
	t_Info$suid = suid;
	t_Info$sgid = sgid;
	t_Info$fsuid = fsuid;
	t_Info$fsgid = fsgid;

	update_value(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 )
		Log::write(LOG, t_Info);

	}

event auditd_place(index: string, action: string, ts: time, node: string, ses: int, pid: int, cwd: string, path_name: string, inode: int, mode: int, ouid: string, ogid: string)
	{
	# ouid/ogid: Refer to the UID and GID of the inode itself. 
	#
	# look up the related record
	local t_Info = get_record(index,pid,ses,node);

	# for now just update the field values
	#  that are related to the current record
	#
	t_Info$cwd = cwd;
	t_Info$path_name = path_name;

	# quick test to look at diff between oxid and xid
	if ( ouid != t_Info$uid ) 	
		print fmt("OUID ERROR ouid: %s uid: %s", ouid, t_Info$uid);

	if ( ogid != t_Info$gid ) 	
		print fmt("OGID ERROR ogid: %s gid: %s", ogid, t_Info$gid);

	update_value(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 ) 
		Log::write(LOG, t_Info);

	}

event auditd_saddr(index: string, action: string, ts: time, node: string, ses: int, pid: int, saddr: string)
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


event auditd_syscall(index: string, action: string, ts: time, node: string, ses: int, pid: int, auid: string, syscall: string, key: string, comm: string, exe: string, a0: string, a1: string, a2: string, uid: string, gid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string, ppid: int, tty: string, success: string, ext: string)
	{
	# look up the related record
	local t_Info = get_record(index,pid,ses,node);

	# for now just update the field values
	# only update the action for some types
	t_Info$action = action;
	t_Info$ts = ts;
	t_Info$ses = ses;
	t_Info$pid = pid;
	#
	t_Info$syscall = syscall;
	t_Info$key = key;
	t_Info$comm = comm;
	t_Info$exe = exe;
	t_Info$a0 = a0;
	t_Info$a1 = a1;
	t_Info$a2 = a2;
	t_Info$ppid = ppid;
	t_Info$tty = tty;
	t_Info$success = success;
	t_Info$ext = ext;
	# identification
	t_Info$uid = uid;
	t_Info$gid = gid;
	t_Info$auid = auid;
	t_Info$euid = euid;
	t_Info$egid = egid;
	t_Info$suid = suid;
	t_Info$sgid = sgid;
	t_Info$fsuid = fsuid;
	t_Info$fsgid = fsgid;

	update_value(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 )
		Log::write(LOG, t_Info);
	}

event auditd_user(index: string, action: string, ts: time, node: string, ses: int, pid: int, auid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string, uid: string, gid: string, exe: string, terminal: string, success: string, ext: string, msg: string)
	{
	# look up the related record
	local t_Info = get_record(index,pid,ses,node);

	# for now just update the field values
	# only update the action for some types
	t_Info$action = action;
	t_Info$ts = ts;
	t_Info$ses = ses;
	t_Info$pid = pid;
	#
	t_Info$msg = msg;
	t_Info$exe = exe;
	t_Info$terminal = terminal;
	t_Info$success = success;
	t_Info$ext = ext;
	# identification
	t_Info$uid = uid;
	t_Info$gid = gid;
	t_Info$auid = auid;
	t_Info$euid = euid;
	t_Info$egid = egid;
	t_Info$suid = suid;
	t_Info$sgid = sgid;
	t_Info$fsuid = fsuid;
	t_Info$fsgid = fsgid;

	update_value(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 )
		Log::write(LOG, t_Info);
	}
	

event bro_init() &priority = 5
{
	  Log::create_stream(AUDITD_CORE::LOG, [$columns=Info]);
}
