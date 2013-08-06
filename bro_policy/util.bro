## ----- functions ----- ##
#
# utility functions for converting string types to native values
#   as well as the Info and identity data structures and the data
#   tables shared by all other policies ...
#
	const ID_DEFAULT = "-1";
	const INFO_NULL  = "NULL";

	const zero_int: int = 0;	

	# Used to keep track of the assigned *id/*gid values for a per host session identity.
	#   This is the description of the who in an auditable event.  It needs to be stored
	#   separately from the Info record since it lives for the entire duration of the session
	#   rather than the individual event.
	#
	# It is logged as a component of the Info record, and updated at a:b:1 for the primary
	#   / alpha record.
	#
	type identity: record {
		ses:       int &log &default=-1;       	        # numeric session id or 'unset'
		node:   string &log &default="NULL";            # what host is this happening on
		## -- identity info (process) --
		auid:   string &log &default=ID_DEFAULT;	# audit id, immutable even if id changes
		uid:    string &log &default=ID_DEFAULT;	# user id
		gid:    string &log &default=ID_DEFAULT;	# group id
		euid:   string &log &default=ID_DEFAULT;	# effective user id
		egid:   string &log &default=ID_DEFAULT;	# effective group id
		suid:   string &log &default=ID_DEFAULT;	# set user id
		sgid:   string &log &default=ID_DEFAULT;	# set group id
		## -- identity info (file system) --
		fsuid:  string &log &default=ID_DEFAULT;	# file system user id
		fsgid:  string &log &default=ID_DEFAULT;	# file system group id
		};
	

	# Track action characteristics - this is defined as the aggrigate characteristics of
	#   an individual auditable event not defined in the identity object.  This is the description
	#   of what happened rather than who did it.
	#
	type Info: record {
		## -- indexing information --
		ts:        time   &log;				#
		i:         identity &log;			# identity structure defined above
		index:     string &log &default=INFO_NULL;	# identifier provided by key in getid()
		node:      string &log &default=INFO_NULL;	# what host is this happening on
		pid:       int    &log &default=-1;		# curent pid
		ses:       int    &log &default=-1;		# numeric session id or 'unset'

		## -- class info --
		action:    string &log &default=INFO_NULL;	# class of action (ex: 'SYSCALL_OBJ'), also ERROR_FLAG
		key:       string &log &default=INFO_NULL;	# subtype of class (ex: 'SYS_NET')

		## -- what happened --
		syscall:   string &log &default=INFO_NULL;	# syscall name
		comm:      string &log &default=INFO_NULL;	# name as appears in 'ps'
		exe:       string &log &default=INFO_NULL;	# full exe name + path

		## -- details --
		msg:       string &log &default=INFO_NULL;
		s_type:    string &log &default=INFO_NULL;	# name or file type socket
		s_host:    string &log &default=INFO_NULL;	# *where* the socket type is pointing
		s_serv:    string &log &default=INFO_NULL;	# service it is pointing to
		path_name: string &log &default=INFO_NULL;	# gen 1x per path element passed to syscall
		cwd:       string &log &default=INFO_NULL;	# current working direct at time of syscall
		a0:        string &log &default=INFO_NULL;	# argument0 to syscall
		a1:        string &log &default=INFO_NULL;	# ..
		a2:        string &log &default=INFO_NULL;	# ..
		arg_t:     string &log &default=INFO_NULL;	# for exec, *total* set of args
		ppid:      int    &log &default=-1; 		# parent pid
		tty:       string &log &default=INFO_NULL; 	# tty type or NO_TTY
		terminal:  string &log &default=INFO_NULL; 	# terminal data or NO_TERM
		success:   string &log &default=INFO_NULL;	# if syscall succedded or not 
		ext:       string &log &default=INFO_NULL;	# exit code for call
		ouid:      string &log &default=INFO_NULL;	# uid on file system inode
		ogid:      string &log &default=INFO_NULL;	# gid on file system inode
		};

	# main state table: driven by *key*
	global actionState: table[string] of Info;
	global identityState: table[string] of identity;	

	### --- ## --- ###
	# End of data structs

	## regx to test data types
	global kv_splitter: pattern = / / &redef;
	global count_match: pattern = /^[0-9]{1,16}$/;
	global port_match: pattern = /^[0-9]{1,5}\/(tcp|udp|icmp)$/;
	global time_match: pattern = /^[0-9]{9,10}.[0-9]{0,6}$/;
	global ip_match: pattern = /((\d{1,2})|(1\d{2})|(2[0-4]\d)|(25[0-5]))/;

	global v16: vector of count = vector(2,3,4,5,6,7,8,9,10,11,12,13,14,15,16);
	global v2s: vector of count = vector(2,4,6);

	## These are token values that will represent a failed conversion
	#   when I grow up I am going to use a data type that includes both 
	#   a return value and an error code.
	#
	const ADDR_CONV_ERROR: addr = 127.4.3.2;
	const TIME_CONV_ERROR: time = double_to_time( to_double("0.000001"));
	const PORT_CONV_ERROR: port = 0/tcp;
	const INT_CONV_ERROR: int = -100;
	const STRING_CONV_ERROR: string = "SCERROR";

	#
	const DATA_NULL:          count = 3;
	const DATA_PATTERN_ERROR: count = 2;
	const DATA_CONV_ERROR:    count = 1;
	const DATA_NOERROR:       count = 0;

	# for a0 of socket call define the /domain/
	const AF_UNIX         1               /* local to host (pipes) */
	const AF_INET         2               /* internetwork: UDP, TCP, etc. */

	# For a1 of the socket call, you define the socket /type/
	#  this is both a handy reference and a way of making the data
	#  more human readable....
	#
	const SOCK_STREAM: count = 1	# stream socket 
	const SOCK_DGRAM: count =  2	# datagram socket
	const SOCK_RAW: count =    3	# raw-protocol interface


	#
	# Return data structure which includes both an (non)error code
	#   as well as the raw data types.
	type time_return: record {
		data: time &default = TIME_CONV_ERROR;
		ret: count &default = DATA_NULL;
		};

	type string_return: record {
		data: string &default = STRING_CONV_ERROR;
		ret: count &default = DATA_NULL;
		};

function s_time(s: string) : time_return
	{
	# default return value is 0.00000 which is the error token
	local ret_val: time_return;

	local mpr = match_pattern(s, time_match);

	if ( mpr$matched ) {
		ret_val$ret = DATA_NOERROR;
		ret_val$data  = double_to_time( to_double(s));
		}
	else {
		ret_val$ret = DATA_PATTERN_ERROR;
		print fmt("TIME PATTERN ERROR: %s", s);
		}

	return ret_val;
	}

function s_string(s: string) : string_return
	{
	# substitute '+' with a space
	local sub_s = subst_string( s, "+", " ");
	local ret_str: string_return;

	# Note that the value of ret_string should be consitered dangerous
	#  as the content can contain terminal control characters etc etc.
	ret_str$data = raw_unescape_URI( sub_s );

	# remove backspace characters and some other goop.  Most of this
	#  is driven from the iSSHD code, but you might as well keep it
	#  around in case there is hyjinx in the air re user input ...
	ret_str$data = edit(ret_str$data, "\x08");
	ret_str$data = edit(ret_str$data, "\x7f");
	# goop
	ret_str$data = gsub(ret_str$data, /\x0a/, "");
	ret_str$data = gsub(ret_str$data, /\x1b\x5b\x30\x30\x6d/, "");
	ret_str$data = gsub(ret_str$data, /\x1b\x5b./, "");

	# now scrape out all the binary goo that might still
	#   be sitting around waiting to cause problems for us ....
	ret_str$data = escape_string(ret_str$data);	
	ret_str$ret = DATA_NOERROR;

	return ret_str;
	}


function s_count(s: string) : count
	{
	local ret_val: count = 0;

	local mpr = match_pattern( s, count_match);

	if ( mpr$matched )
		ret_val =  to_count(s);
	else 
		print fmt("COUNT PATTERN ERROR: %s", s);

	return ret_val;
	}

function s_addr(s: string) : addr
	{
	local ret_val:addr = ADDR_CONV_ERROR;

	local mpr = match_pattern(s_host, ip_match);

	if ( mpr$matched ) {
		ret_val = to_addr(s);
		}
	else {
		print fmt("ADDR PATTERN ERROR: %s", s);
		}

	return ret_val;
	}

function s_port(s: string) : port
	{
	local ret_val = PORT_CONV_ERROR;

	# test to see if the "value" component is missing the protocol string
	local t_port = s;
	local p_pm = match_pattern( t_port, port_match );

	if ( p_pm$matched ) {
		ret_val = to_port(t_port);
		}	
	else {
		local c_pm = match_pattern( t_port, count_match );

		if ( c_pm$matched ) {
			t_port = fmt("%s/tcp", t_port);
			ret_val = to_port(t_port);
			}
		}

	return ret_val;
	}

function s_int(s: string) : int
	{
	local ret_val:int = INT_CONV_ERROR;

	ret_val = to_int(s);
	return ret_val;
	}


