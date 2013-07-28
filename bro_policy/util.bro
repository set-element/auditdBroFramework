## ----- functions ----- ##
#
# utility functions for converting string types to native values
#

	## regx to test data types
	global kv_splitter: pattern = / / &redef;
	global count_match: pattern = /^[0-9]{1,16}$/;
	global port_match: pattern = /^[0-9]{1,5}\/(tcp|udp|icmp)$/;
	global time_match: pattern = /^[0-9]{9,10}.[0-9]{0,6}$/;

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

	ret_val = to_addr(s);

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


