# auditd_input_stream.bro
#  Scott Campbell
#
# note on syntax: The traditional "thing that happens" in auditd is called an 'event' 
#  which is clearly an issue, so I am renaming them 'action'.  Actions are composed of
#  of records, which are themselves composed of fields.
#
# note: to address the NULL = '-1' issue with counts, ints and whatnot, there will be 
#       no use of count types in the event stream.  Makes life just that much simpler!
#       For user identificaton just ue a string type since the id will normally be a
#       legitimate account.
#
@load util
#@load auditd_core

@load frameworks/communication/listen
@load base/frameworks/input

module AUDITD_IN_STREAM;

export {

	redef InputAscii::empty_field = "EMPTY";
	global kv_splitter: pattern = / /;

	type lineVals: record {
		d: string;
	};

	const data_file = "/tmp/df.log";

	const dispatcher: table[string] of function(_data: string): count &redef;
	}

function execve_f(data: string) : count
	{
	# data format:
	# 1492:2 EXECVE_OBJ EXECVE 1357649135.905 3 %20/bin/csh%20-f%20/usr/common/usg/bin/nersc_host
	local parts = split(data, kv_splitter);

	local index = s_string( parts[1] );	# form a:b, a=action count, b=which record in action
	local flavor = s_string( parts[2] );	# base object type
	local action = s_string( parts[3] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = s_time( parts[4] );		# time of record
	local node = s_string( parts[5] );
	local ses = s_int( parts[6] );		# login session ID
	local pid = s_int( parts[7] );		# Process id
	#
	local argc = s_int( parts[8] );		# number of arguments for exec (starts at 1)
	local argument = s_string( parts[9] );	# total argument string

	event auditd_execve(index$data, action$data, ts$data, node$data, ses, pid, argc, argument$data);
	#event AUDITD_CORE::auditd_execve(index, action, ts, node, ses, pid, argc, argument);

	return 0;
	}

function generic_f(data: string) : count
	{
	# 65465:2 GENERIC_OBJ FD_PAIR 1357648201.328 mndlint01 0 NULL NULL NULL NULL NULL NULL -1 -1 -1 -1 -1 -1
	# -1 -1 -1 -1 NULL NULL NULL 0
	local parts = split(data, kv_splitter);

	local index = s_string( parts[1] );	# form a:b, a=action count, b=which record in action
	local flavor = s_string( parts[2] );	# base object type
	local action = s_string( parts[3] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = s_time( parts[4] );		# time of record
	local node = s_string( parts[5] );	# host data originated from
	#
	local auid = s_string( parts[6] );
	local key = s_string( parts[7] ); 
	local comm = s_string( parts[8] );
	local exe = s_string( parts[9] );
	local a0 = s_string( parts[10] );
	local a1 = s_string( parts[11] );
	local a2 = s_string( parts[12] );
	local uid = s_string( parts[13] );
	local gid = s_string( parts[14] );
	local euid = s_string( parts[15] );
	local egid = s_string( parts[16] );
	local fsuid = s_string( parts[17] );
	local fsgid = s_string( parts[18] );
	local suid = s_string( parts[19] );
	local sgid = s_string( parts[20] );
	local pid = s_int( parts[21] );
	local ppid = s_int( parts[22] );
	local ses = s_int( parts[23] );
	local tty = s_string( parts[24] );
	local terminal = s_string( parts[25] );
	local success = s_string( parts[26] );
	local ext = s_string( parts[27] );	

	event auditd_generic(index$data, action$data, ts$data, node$data, ses, pid, auid$data, comm$data, exe$data, a0$data, a1$data, a2$data, uid$data, gid$data, euid$data, egid$data, fsuid$data, fsgid$data, suid$data, sgid$data, ppid, tty$data, terminal$data, success$data, ext$data);

	return 0;
	}

function place_f(data: string) : count
	{
	# 13:2 PLACE_OBJ CWD 1357669891.417 mndlint01 /chos/global/project/projectdirs/mendel/ganglia NULL -1 -1
	# 13:3 PLACE_OBJ PATH 1357669891.417 mndlint01 NULL rrds/Mendel%20Compute/mc0867.nersc.gov/.cpu_idle.rrd.
	#                       6ITCyp 252651183 0100600 unknown(65534) unknown(65533)
	local parts = split(data, kv_splitter);

	local index = s_string( parts[1] );	# form a:b, a=action count, b=which record in action
	local flavor = s_string( parts[2] );	# base object type
	local action = s_string( parts[3] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = s_time( parts[4] );		# time of record
	local node = s_string( parts[5] );	# host data originated from
	local ses = s_int( parts[6] );
	local pid = s_int( parts[7] );
	#
	local cwd = s_string( parts[8] );
	local path_name = s_string( parts[9] );
	local inode = s_int( parts[10] );
	local mode = s_int( parts[11] );
	local ouid = s_string( parts[12] );
	local ogid = s_string( parts[13] );

	event auditd_place(index$data, action$data, ts$data, node$data, ses, pid, cwd$data, path_name$data, inode, mode, ouid$data, ogid$data);
	return 0;
	}

function saddr_f(data: string) : count
	{
	# 1433:2 SADDR_OBJ SOCKADDR 1357670401.886 netlink%20pid%3A0
	# 24142:2 SADDR_OBJ SOCKADDR 1357648977.688 inet%20host%3A208.45.140.197%20serv%3A80
	local parts = split(data, kv_splitter);

	local index = s_string( parts[1] );	# form a:b, a=action count, b=which record in action
	local flavor = s_string( parts[2] );	# base object type
	local action = s_string( parts[3] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = s_time( parts[4] );		# time of record
	local node = s_string( parts[5] );	# host data originated from
	local ses = s_int( parts[6] );
	local pid = s_int( parts[7] );
	#
	local saddr = s_string( parts[8] );	# address object (local or inet)

	event auditd_saddr(index$data, action$data, ts$data, node$data, ses, pid, saddr$data);
	return 0;
	}

function syscall_f(data: string) : count
	{
	# 9:1 SYSCALL_OBJ SYSCALL 1357669891.416 mndlint01 root chmod SYS_FILE_PERM rsync /usr/bin/rsync 7ffff282
	#                           1570 1a4 8000 root root root root root root root root 19220 19206 NO_TTY chmod yes 0
	local parts = split(data, kv_splitter);

	local index = s_string( parts[1] );	# form a:b, a=action count, b=which record in action
	local flavor = s_string( parts[2] );	# base object type
	local action = s_string( parts[3] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = s_time( parts[4] );		# time of record
	local node = s_string( parts[5] );
	#
	local ses = s_int( parts[6] );		# login session ID
	local auid = s_string( parts[7] );
	local syscall = s_string( parts[8] );
	local key = s_string( parts[9] ); 
	local comm = s_string( parts[10] );
	local exe = s_string( parts[11] );
	local a0 = s_string( parts[12] );
	local a1 = s_string( parts[13] );
	local a2 = s_string( parts[14] );
	local uid = s_string( parts[15] );
	local gid = s_string( parts[16] );
	local euid = s_string( parts[17] );
	local egid = s_string( parts[18] );
	local fsuid = s_string( parts[19] );
	local fsgid = s_string( parts[20] );
	local suid = s_string( parts[21] );
	local sgid = s_string( parts[22] );
	local pid = s_int( parts[23] );
	local ppid = s_int( parts[24] );
	local tty = s_string( parts[25] );
	#local terminal = s_string( parts[26] );
	local success = s_string( parts[26] );
	local ext = s_string( parts[27] );

	event auditd_syscall(index$data, action$data, ts$data, node$data, ses, pid, auid$data, syscall$data, key$data, comm$data, exe$data, a0$data, a1$data, a2$data, uid$data, gid$data, euid$data, egid$data, fsuid$data, fsgid$data, suid$data, sgid$data, ppid, tty$data, success$data, ext$data);
	#event auditd_syscall(index, action, ts, node, ses, pid, auid, syscall, key, comm, exe, a0, a1, a2, uid, gid, euid, egid, fsuid, fsgid, suid, sgid, ppid, tty, terminal, success, ext);
	return 0;
	}

function user_f(data: string) : count
	{
	# 2500:1 USER_OBJ USER_ACCT 1357649165.26 mndlint01 0 scottc -1 -1 -1 -1 -1 -1 -1 scottc NULL 0 /chos/dev
	#                           /pts/1 /bin/su
	local parts = split(data, kv_splitter);

	local index = s_string( parts[1] );	# form a:b, a=action count, b=which record in action
	local flavor = s_string( parts[2] );	# base object type
	local action = s_string( parts[3] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = s_time( parts[4] );		# time of record
	local node = s_string( parts[5] );
	#
	local ses = s_int( parts[6] );
	local auid = s_string( parts[7] );
	local egid = s_string( parts[8] );
	local euid = s_string( parts[9] );
	local fsgid = s_string( parts[10] );
	local fsuid = s_string( parts[11] );
	local gid = s_string( parts[12] );
	local suid = s_string( parts[13] );
	local sgid = s_string( parts[14] );
	local uid = s_string( parts[15] );
	local pid = s_int( parts[16] );
	local success = s_string( parts[17] );
	local ext = s_string( parts[18] );
	local terminal = s_string( parts[19] );
	local exe = s_string( parts[20] );
	local msg = s_string( parts[21] );

	event auditd_user(index$data, action$data, ts$data, node$data, ses, pid, auid$data, euid$data, egid$data, fsuid$data, fsgid$data, suid$data, sgid$data, uid$data, gid$data, exe$data, terminal$data, success$data, ext$data, msg$data);
	return 0;
	}

redef dispatcher += {
	["EXECVE_OBJ"] = execve_f,
	["GENERIC_OBJ"] = generic_f,
	["PLACE_OBJ"] = place_f,
	["SADDR_OBJ"] = saddr_f,
	["SYSCALL_OBJ"] = syscall_f,
	["USER_OBJ"] = user_f,
	};

#event line(description: Input::EventDescription, tpe: Input::Event, _data: string)
event line(description: Input::EventDescription, tpe: Input::Event, LV: lineVals)
	{
	# Each line is fed to this event where it is digested and sent to the dispatcher 
	#  for appropriate processing

	# Data line looks like:
	# 9:1 SYSCALL_OBJ SYSCALL 1357669891.416 mndlint01 ...
	# ID, GENERAL-TYPE, TYPE, TIME, HOST ...
	# Each of the general types has a given structure, and the index ties all
	#  related 
	local parts = split(LV$d, kv_splitter);
	local event_name = parts[2];

	if ( event_name in dispatcher ) 
		dispatcher[event_name](LV$d);
	}	


event bro_init()
	{
	Input::add_event([$source=data_file, $reader=Input::READER_RAW, $mode=Input::STREAM, $name="auditd", $fields=lineVals, $ev=line]);
	}

