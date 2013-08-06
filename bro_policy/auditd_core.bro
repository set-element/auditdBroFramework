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

	const ID_DEFAULT = "-1";
	const INFO_NULL  = "NULL";

	const zero_int: int = 0;	

	# to map identity <=> action use sid:node as "identity-id"
	# to map action-id and record[n] use index:node as "action-id"

	# exported functions
	global get_action_id: function(index: string, node: string) : string;
	global get_identity_id: function(ses: int, node: string) : string;
	global get_action_obj: function(index: string, node: string) : Info;
	global get_identity_obj: function(ses: int, node: string) : identity;
	global sync_identity: function(index: string, node: string) : Info;
	global copy_identity: function(index: string, node: string) : Info;
	global delete_action: function(index: string, node: string);
	global string_test: function(s: string) : bool;
	global int_test: function(i: int) : bool;
	global time_test: function(t: time) : bool;
	global last_record: function(index: string): count;
	global update_action: function(i: Info);
	global update_identity: function(ses: int, node: string, auid: string, uid: string, gid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string) : count;

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

	#print fmt("index: %s key: %s", index, key);

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
		t_Info$index = index;
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

function copy_identity(index: string, node: string) : Info
{
	# Take identity and sync it with the action structure
	local t_Info = get_action_obj(index,node);
	local t_identity = get_identity_obj(t_Info$ses, t_Info$node);

	t_Info$i = t_identity;

	return t_Info;
}

function sync_identity(index: string, node: string) : Info
{
	# Take identity and sync it with the action structure
	local t_Info = get_action_obj(index,node);
	local t_identity = get_identity_obj(t_Info$ses, t_Info$node);

	t_Info$i = t_identity;

	local key = get_action_id(t_Info$index,t_Info$node);
	actionState[key] = t_Info;		

	return t_Info;
}

function delete_action(index: string, node: string)
{
	# remove action obj
	local key = get_action_id(index,node);

	if ( key in actionState )
		delete actionState[key];
}

function string_test(s: string) : bool
{
	# Here we test for an error condition on the input framework conversion,
	#   or a default value in the field (which could write over pre-existing
	#   data.
	local ret = T;

	if ( (s == STRING_CONV_ERROR) || (s == ID_DEFAULT) || (s == INFO_NULL) )
		ret = F;

	return ret;
}

function int_test(i: int) : bool
{
	# Here we test for an error condition on the input framework conversion,
	#   or a default value in the field (which could write over pre-existing
	#   data.
	local ret = T;

	if ( (i == INT_CONV_ERROR) || (i == -1) )
		ret = F;

	return ret;
}

function time_test(t: time) : bool
{
	# Here we test for an error condition on the input framework conversion,
	#   or a default value in the field (which could write over pre-existing
	#   data.
	local ret = T;

	if ( t == TIME_CONV_ERROR )
		ret = F;

	return ret;
}

function update_identity(ses: int, node: string, auid: string, uid: string, gid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string) : count
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
	if ( int_test(ses) )
		t_identity$ses = ses;

	if ( string_test(node) ) 
		t_identity$node = node;
	
	if ( string_test(auid) )
		t_identity$auid = auid;

	if ( string_test(uid) )
		t_identity$uid = uid;

	if ( string_test(gid) )
		t_identity$gid = gid;

	if ( string_test(euid) )
		t_identity$euid = euid;

	if ( string_test(egid) )
		t_identity$egid = egid;

	if ( string_test(fsuid) )
		t_identity$fsuid = fsuid;

	if ( string_test(fsgid) )
		t_identity$fsgid = fsgid;

	if ( string_test(suid) )
		t_identity$suid = suid;

	if ( string_test(sgid) )
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

	# update field values if they are not error or default values
	
	if ( string_test(action) )
		t_Info$action = action;
	
	if ( time_test(ts) )
		t_Info$ts = ts;
	
	if ( int_test(ses) )
		t_Info$ses = ses;

	if ( int_test(pid) )
		t_Info$pid = pid;
	
	if ( string_test(argument) )
		t_Info$arg_t = argument;

	update_action(t_Info);

	# if the last record, print it and clean up the action state
	if ( last_record(index) == 1 ) {
@ifdef ( AUDITD_CORE::AUDITD_POLICY_LOAD )
		#auditd_policy_dispatcher(copy_identity(index,node));
		local i = copy_identity(index,node);
		event AUDITD_POLICY::auditd_policy_dispatcher(i);
		#print fmt("%s", AUDITD_POLICY::AUDITD_POLICY_LOAD 
		event s("hello");
@endif
		t_Info = sync_identity(index,node);
		Log::write(LOG, t_Info);
		delete_action(index,node);
		}

	} # end auditd_execve


event auditd_generic(index: string, action: string, ts: time, node: string, ses: int, pid: int, auid: string, comm: string, exe: string, a0: string, a1: string, a2: string, uid: string, gid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string, ppid: int, tty: string, terminal: string, success: string, ext: string)
	{
	# Alpha event
	# look up the related record
	local t_Info = get_action_obj(index,node);

	# update field values if they are not error or default values
	#
	if ( string_test(index) )
		t_Info$index = index;

	if ( string_test(action) )
		t_Info$action = action;
	
	if ( time_test(ts) )
		t_Info$ts = ts;
	
	if ( int_test(ses) )
		t_Info$ses = ses;

	if ( int_test(pid) )
		t_Info$pid = pid;

	## ----- ##
	
	if ( string_test(comm) )
		t_Info$comm = comm;

	if ( string_test(exe) )
		t_Info$exe = exe;

	if ( string_test(a0) )
		t_Info$a0 = a0;

	if ( string_test(a1) )
		t_Info$a1 = a1;

	if ( string_test(a2) )
		t_Info$a2 = a2;

	if ( int_test(ppid) )
		t_Info$ppid = ppid;

	if ( string_test(tty) )
		t_Info$tty = tty;

	if ( string_test(terminal) )
		t_Info$terminal = terminal;

	if ( string_test(success) )
		t_Info$success = success;

	if ( string_test(ext) )
		t_Info$ext = ext;

	# identification
	update_identity(ses, node, auid, uid, gid, euid, egid, fsuid, fsgid, suid, sgid);

	update_action(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 ) {
@ifdef ( AUDITD_POLICY::AUDITD_POLICY_LOAD )
		#auditd_policy_dispatcher(copy_identity(index,node));
		event AUDITD_POLICY::auditd_policy_dispatcher(copy_identity(index,node));
@endif
		t_Info = sync_identity(index,node);
		Log::write(LOG, t_Info);
		delete_action(index,node);
		}

	} # end auditd_generic event

event auditd_place(index: string, action: string, ts: time, node: string, ses: int, pid: int, cwd: string, path_name: string, inode: int, mode: int, ouid: string, ogid: string)
	{
	# Beta event
	# ouid/ogid: Refer to the UID and GID of the inode itself. 
	#
	# look up the related record
	local t_Info = get_action_obj(index,node);

	# update field values if they are not error or default values
	if ( int_test(ses) )
		t_Info$ses = ses;

	if ( string_test(cwd) )	
		t_Info$cwd = cwd;

	if ( string_test(path_name) )
		t_Info$path_name = path_name;

	if ( string_test(ouid) )
		t_Info$ouid = ouid;

	if ( string_test(ogid) )
		t_Info$ogid = ogid;

	update_action(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 ) {
@ifdef ( AUDITD_POLICY::AUDITD_POLICY_LOAD )
		#auditd_policy_dispatcher(copy_identity(index,node));
		event AUDITD_POLICY::auditd_policy_dispatcher(copy_identity(index,node));
@endif
		t_Info = sync_identity(index,node);
		Log::write(LOG, t_Info);
		delete_action(index,node);
		}

	} # end event auditd_place

event auditd_saddr(index: string, action: string, ts: time, node: string, ses: int, pid: int, saddr: string)
	{

	# most of the work here will be in decoding the saddr structure
	#
	# common types:
	# 	inet host 1.2.3.4 serv:123
	# 	local /dev/filename
	# 	netlink /dev/log
	#
	# will be broken out into the following structures
	#
	# 	type : {inet host|local|netlink}
	# 	host : {file|device|ip} identifies where
	# 	serv : {port} (optional) identifies what
	#
	
	local t_Info = get_action_obj(index,node);

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

		if ( string_test(stype) )
			t_Info$s_type = stype;

		if ( string_test(t_host[2]) )
			t_Info$s_host = t_host[2];

		if ( string_test(t_serv[2]) )
			t_Info$s_serv = t_serv[2];

		}
	else if ( stype == "local" ) {
	
		if ( string_test(stype) )	
			t_Info$s_type = stype;

		if ( string_test(host) )
			t_Info$s_host = host;

		} 
	else if ( stype == "netlink" ) {

		if ( string_test(stype) )	
			t_Info$s_type = stype;

		if ( string_test(t_host[2]) )
			t_Info$s_host = t_host[2];
		
		}

	update_action(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 ) {
@ifdef ( AUDITD_POLICY::AUDITD_POLICY_LOAD )
		#auditd_policy_dispatcher(copy_identity(index,node));
		event AUDITD_POLICY::auditd_policy_dispatcher(copy_identity(index,node));
@endif
		t_Info = sync_identity(index,node);
		Log::write(LOG, t_Info);
		delete_action(index,node);
		}

	} # end event auditd_saddr


event auditd_syscall(index: string, action: string, ts: time, node: string, ses: int, pid: int, auid: string, syscall: string, key: string, comm: string, exe: string, a0: string, a1: string, a2: string, uid: string, gid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string, ppid: int, tty: string, success: string, ext: string)
	{
	# look up the related record
	local t_Info = get_action_obj(index,node);

	# update field values if they are not error or default values
	if ( string_test(index) )
		t_Info$index = index;

	if ( string_test(action) )
		t_Info$action = action;

	if ( time_test(ts) )
		t_Info$ts = ts;	

	if ( int_test(ses) )
		t_Info$ses = ses;

	if ( int_test(pid) )
		t_Info$pid = pid;
	#

	if ( string_test(syscall) )
		t_Info$syscall = syscall;

	if ( string_test(key) )
		t_Info$key = key;

	if ( string_test(comm) )
		t_Info$comm = comm;

	if ( string_test(exe) )
		t_Info$exe = exe;

	if ( string_test(a0) )
		t_Info$a0 = a0;

	if ( string_test(a1) )
		t_Info$a1 = a1;

	if ( string_test(a2) )
		t_Info$a2 = a2;

	if ( int_test(ppid) )
		t_Info$ppid = ppid;

	if ( string_test(tty) )
		t_Info$tty = tty;

	if ( string_test(success) )
		t_Info$success = success;

	if ( string_test(ext) )
		t_Info$ext = ext;

	# identification
	update_identity(ses, node, auid, uid, gid, euid, egid, fsuid, fsgid, suid, sgid);

	update_action(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 ) {
@ifdef ( AUDITD_POLICY::AUDITD_POLICY_LOAD )
		#auditd_policy_dispatcher(copy_identity(index,node));
		event AUDITD_POLICY::auditd_policy_dispatcher(copy_identity(index,node));
@endif
		t_Info = sync_identity(index,node);
		Log::write(LOG, t_Info);
		delete_action(index,node);
		}

	} # end event auditd_syscall

event auditd_user(index: string, action: string, ts: time, node: string, ses: int, pid: int, auid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string, uid: string, gid: string, exe: string, terminal: string, success: string, ext: string, msg: string)
	{
	# look up the related record
	local t_Info = get_action_obj(index,node);

	# for now just update the field values
	# only update the action for some types
	if ( string_test(index) )
		t_Info$index = index;

	if ( string_test(action) )
		t_Info$action = action;

	if ( time_test(ts) )
		t_Info$ts = ts;

	if ( int_test(ses) )
		t_Info$ses = ses;

	if ( int_test(pid) )
		t_Info$pid = pid;

	## ----- ##

	if ( string_test(msg) )
		t_Info$msg = msg;

	if ( string_test(exe) )
		t_Info$exe = exe;
	
	if ( string_test(terminal) )
		t_Info$terminal = terminal;

	if ( string_test(success) )
		t_Info$success = success;

	if ( string_test(ext) )
		t_Info$ext = ext;

	# identification
	update_identity(ses, node, auid, uid, gid, euid, egid, fsuid, fsgid, suid, sgid);

	update_action(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 ) {
if ( AUDITD_POLICY::AUDITD_POLICY_LOAD )
		#event auditd_policy_dispatcher(copy_identity(index,node));
		event AUDITD_POLICY::auditd_policy_dispatcher(copy_identity(index,node));
#@endif
		t_Info = sync_identity(index,node);
		Log::write(LOG, t_Info);
		delete_action(index,node);
		}

	}
	

event bro_init() &priority = 5
{
	  Log::create_stream(AUDITD_CORE::LOG, [$columns=Info]);
}
