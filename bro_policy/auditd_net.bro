# Accept connection primitives from auditd_policy::network_register_conn()
#  and identify matching network connections.
#
# An interesting problem is that the syscall will get registered immediatly, while
#  more stateful network data may take a while ...


@load util

module AUDITD_NET;

export {

	type socket_data: record {
		domain: count &default=0;
		type: count &default=0;
		ts: time;
		state: count &default=0;
		};

	# data struct to hold socket data
	# index the table via node and ident
	socket_lookup: table[string] of socket_data;

	### ----- Config ----- ###
	global filter_tcp_only = T &redef;

	### ----- Event/Functions ----- ###


	} # end export

# Note on socket state:
# 	0 = new
#	1 = init
#	2 = conn	 -> make connection 
#	3 = bind|listen  -> create listener
#	4 = accept 	 -> listener connect
# 

### ----- # ----- ###
#      Functions
### ----- # ----- ###
function syscall_socket(inf: Info) : count
	{
	# Function test for socket exist.
	# If none, create; if exist, test dt 
	local ret_val = 0;
	local t_socket_data: socket_data;

	local index = fmt("%s%s", inf$ses, inf$node);

	# If this is not a TCP connection, bail ...
	if ( filter_tcp_only && ( (a0 != AF_INET) || (a1 != SOCK_STREAM)))
		return ret_val;

	if ( index !in socket_lookup ) {
	
		t_socket_data$domain = a0;
		t_socket_data$type = a1;
		t_socket_data$ts = ts;
		t_socket_data$state = 1;
	
		ret_val = 1;
		socket_lookup[index] = t_socket_data;

		}
	else {
		# skip for now
		ret_val = 2;
		}

	return ret_val;
	} # syscall_socket end

function syscall_connect(inf: Info) : count
	{
	local ret_val = 0;

	# check to see if the socket struct is in state == 1
	if ( syscall_socket(inf) == 1 ) {

		local index = fmt("%s%s", inf$ses, inf$node);
		socket_lookup[index]$state = 2;

		# The connect() call identifies the time to
		#  register a new connection.  For now it will
		#  be any connection, but filtering can be done 
		#  to limit it to ! is_local() .
		event register_audit_conn(inf);
		ret_val = 1;
		}

	return ret_val;
	} # syscall_connection end


### ----- # ----- ###
#      Events
### ----- # ----- ###

event syscall_register(node: string, ident: identity, ts: time, s_host: string, s_serv: string)
	{
	# convert address and port to real
	local r_addr = s_addr(s_host);
	local r_port = s_port(s_serv);

	if ( (r_addr == ADDR_CONV_ERROR) || (r_port == PORT_CONV_ERROR) )
		return;


	}
