/*
 * inotail.c
 * A fast implementation of tail which uses the inotify API present in
 * recent versions of the Linux kernel.
 *
 * Copyright (C) 2005-2007, Tobias Klauser <tklauser@distanz.ch>
 *
 * The idea was taken from turbotail.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "inotify.h"
#include "inotify-syscalls.h"

#include "auditparse.h"

/* Start of new code ... */
#include <locale.h>
#include <libaudit.h>
#include <auparse.h>
#include "modp_burl.h"

#define PROGRAM_NAME "inotail"
#define DEFAULT_BUFFER_SIZE 4096
/* inotify event buffer length for one file */
#define INOTIFY_BUFLEN (4 * sizeof(struct inotify_event))

/* Soms additional things for the auparse functionality */

/*  Both the ses and pid values will be used for the base lookups in auditd_core.
 *   Because of this, records after the first in an event will be benefited by passing
 *   this information along.  If this is not done, a great deal of state goo and churn
 *   is introduced later in the bro code.
 *  The ses identifier is the primary with the pid as a backup since sid sometimes has
 *   a value of 'unset'.
 */
int holder_size = 256;
char ses_holder[256];
char pid_holder[256];

auparse_state_t *au;
char *aud_buf;

/* Print header with filename before tailing the file? */
static char verbose = 0;

/* Tailing relative to begin or end of file */
static char from_begin = 0;

/* Number of ignored files */
static int n_ignored = 0;

/* Command line options */
static const struct option long_opts[] = {
	{ "bytes", required_argument, NULL, 'c' },
	{ "follow", optional_argument, NULL, 'f' },
	{ "lines", required_argument, NULL, 'n' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 }
};

static void *emalloc(size_t size)
{
	void *ret = malloc(size);

	if (unlikely(!ret)) {
		fprintf(stderr, "Error: Failed to allocate %d bytes of memory (%s)\n", (int)size, strerror(errno));
		exit(EXIT_FAILURE);
	}

	return ret;
}

static char* encode_string(const char* src, const int len)
{
        char *url_enc_string;

        /* take a string and return a pointer to the URI encoded version */
        int new_len = modp_burl_encode_len(len);

        url_enc_string = emalloc(new_len);

        if ( url_enc_string == NULL )
                return (char*)src;
        else

        /*
	 * We do not test the return here since it
	 * is done via the call itself.
	 **/
                modp_burl_encode(url_enc_string, src, len);

        return url_enc_string;
}

static void process_place_obj(auparse_state_t *_au, int *event_cnt, int num_records, int record_cnt)
{
	char* type = "NULL";
	char* t_type = NULL;
	char* node = "localhost";
	char* t_node = NULL;
	char* cwd = "NULL";
	char* t_cwd = NULL;
	char* path_name = "NULL";
	char* t_path_name = NULL;
	char* inode = "NULL";
	char* mode = "NULL";
	char* t_mode = NULL;
	char* ouid = "NULL";
	char* ogid = "NULL";

	int num_fields = auparse_get_num_fields(_au) - 1;
	int n;

	const au_event_t *e = auparse_get_timestamp(au);
	
	if (e == NULL)
		return;

	auparse_first_field(_au);

	for ( n = 0 ; n <= num_fields; n++ ) {

		char* field_name = (char*)auparse_get_field_name(_au);
		
		if ( strcmp(field_name,F_TYPE) == 0 ) {
			type = (char*)auparse_interpret_field(_au);
			t_type = encode_string( type, strlen(type));
			}

		if ( strcmp(field_name, F_NODE) == 0 ) {
			node = (char*)auparse_interpret_field(_au);
			t_node = encode_string( node, strlen(node));
			}

		if ( strcmp(field_name, F_CWD) == 0 ) {
			cwd = (char*)auparse_interpret_field(_au);
			t_cwd = encode_string( cwd, strlen(cwd));
			}

		if ( strcmp(field_name, F_NAME) == 0 ) {
			path_name = (char*)auparse_interpret_field(_au);
			t_path_name = encode_string( path_name, strlen(path_name));
			}

		if ( strcmp(field_name, F_INODE) == 0 )
			inode = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_MODE) == 0 ) {
			mode = (char*)auparse_interpret_field(_au);
			t_mode = encode_string( mode, strlen(mode));
			}

		if ( strcmp(field_name, F_OUID) == 0 )
			ouid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_OGID) == 0 )
			ogid = (char*)auparse_interpret_field(_au);

		auparse_next_field(_au);
		}

	printf("%i:%i:%i PLACE_OBJ %s %u.%u %s %s %s %s %s %s %s %s %s\n", *event_cnt, num_records, record_cnt, t_type, (unsigned)e->sec, e->milli, t_node, ses_holder, pid_holder, t_cwd, t_path_name, inode, t_mode, ouid, ogid);

	free(t_type);
	free(t_node);
	free(t_cwd);
	free(t_path_name);
	free(t_mode);

	return;
}

static void process_user_obj(auparse_state_t *_au, int *event_cnt, int num_records, int record_cnt)
{
	char* type = "NULL";
	char* t_type = NULL;
	char* node = "localhost";
	char* t_node = NULL;

	char* ses = "NULL";
	char* egid = "NULL";
	char* auid = "NULL";
	char* euid = "NULL";
	char* fsgid = "NULL";
	char* fsuid = "NULL";
	char* gid = "NULL";
	char* suid = "NULL";
	char* sgid = "NULL";
	char* uid = "NULL";
	char* pid = "NULL";
	char* ouid = "NULL";
	char* ogid = "NULL";
 
	char* success = "NULL";
	char* xit = "NULL";
	char* t_xit = NULL;
	char* term = "NULL";
	char* exe = "NULL";
	char* t_exe = NULL;

	int num_fields = auparse_get_num_fields(_au) - 1;
	int n;

	const au_event_t *e = auparse_get_timestamp(au);
	
	if (e == NULL)
		return;

	auparse_first_field(_au);

	for ( n = 0 ; n <= num_fields; n++ ) {

		char* field_name = (char*)auparse_get_field_name(_au);
		
		if ( strcmp(field_name,F_TYPE) == 0 ) {
			type = (char*)auparse_interpret_field(_au);
			t_type = encode_string( type, strlen(type));
			}

		if ( strcmp(field_name, F_NODE) == 0 ) {
			node = (char*)auparse_interpret_field(_au);
			t_node = encode_string( node, strlen(node));
			}

		if ( strcmp(field_name, F_SES) == 0 )
			ses = (char*)auparse_get_field_str(_au);

		if ( strcmp(field_name, F_EGID) == 0 )
			egid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_AUID) == 0 )
			auid = (char*)auparse_get_field_str(_au);

		if ( strcmp(field_name, F_EUID) == 0 )
			euid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_FSGID) == 0 )
			fsgid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_FSUID) == 0 )
			fsuid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_GID) == 0 )
			gid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_SUID) == 0 )
			suid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_SGID) == 0 )
			sgid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_UID) == 0 )
			uid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_PID) == 0 )
			pid = (char*)auparse_get_field_str(_au);

		if ( strcmp(field_name, F_AUID) == 0 )
			ouid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_OGID) == 0 )
			ogid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_SUCCESS) == 0 )
			success = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_EXIT) == 0 ) {
			xit = (char*)auparse_interpret_field(_au);
			t_xit = encode_string( xit, strlen(xit));
			}

		if ( strcmp(field_name, F_TERM) == 0 )
			term = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_EXE) == 0 ) {
			exe = (char*)auparse_interpret_field(_au);
			t_exe = encode_string( exe, strlen(exe));
			}

		auparse_next_field(_au);
		}

	strncpy(ses_holder,ses,holder_size);
	strncpy(pid_holder,pid,holder_size);

//22
	printf("%i:%i:%i USER_OBJ %s %u.%u %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n", *event_cnt, num_records, record_cnt, t_type, (unsigned)e->sec, e->milli, t_node, ses, auid, egid, euid, fsgid, fsuid, gid, suid, sgid, uid, pid, success, t_xit, term, t_exe);

	free(t_node);
	free(t_type);
	free(t_xit);
	free(t_exe);

	return;
}

static void process_syscall_obj(auparse_state_t *_au, int *event_cnt, int num_records, int record_cnt)
{

	char* type = "NULL";
	char* t_type = NULL;
	char* node = "localhost";
	char* t_node = NULL;
	char* ses = "NULL";
	char* auid = "NULL";

	char* egid = "NULL";
	char* euid = "NULL";
	char* fsgid = "NULL";
	char* fsuid = "NULL";
	char* gid = "NULL";
	char* suid = "NULL";
	char* sgid = "NULL";
	char* uid = "NULL";

	char* comm = "NULL";
	char* t_comm = NULL;
	char* exe = "NULL";
	char* t_exe = NULL;
	char* a0 = "NULL";
	char* t_a0 = NULL;
	char* a1 = "NULL";
	char* t_a1 = NULL;
	char* a2 = "NULL";
	char* t_a2 = NULL;
	char* pid = "NULL";
	char* ppid = "NULL";
	char* success = "NULL";
	char* xit = "NULL";
	char* t_xit = NULL;
	char* tty = "NULL";
	char* key = "NULL";
	char* sysc_name = "NULL";
 
	int num_fields = auparse_get_num_fields(_au) - 1;
	int n;

	const au_event_t *e = auparse_get_timestamp(au);
	
	if (e == NULL)
		return;

	auparse_first_field(_au);

	for ( n = 0 ; n <= num_fields; n++ ) {

		char* field_name = (char*)auparse_get_field_name(_au);

		if ( strcmp(field_name,F_TYPE) == 0 ) {
			type = (char*)auparse_interpret_field(_au);
			t_type = encode_string( type, strlen(type));
			}

		if ( strcmp(field_name, F_NODE) == 0 ) {
			node = (char*)auparse_interpret_field(_au);
			t_node = encode_string( node, strlen(node));
			}

		if ( strcmp(field_name, F_SES) == 0 )
			ses = (char*)auparse_get_field_str(_au);

		if ( strcmp(field_name, F_EGID) == 0 )
			egid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_AUID) == 0 )
			auid = (char*)auparse_get_field_str(_au);

		if ( strcmp(field_name, F_EUID) == 0 )
			euid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_FSGID) == 0 )
			fsgid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_FSUID) == 0 )
			fsuid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_GID) == 0 )
			gid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_SUID) == 0 )
			suid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_SGID) == 0 )
			sgid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_UID) == 0 )
			uid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_COMM) == 0 ) {
			comm = (char*)auparse_interpret_field(_au);
			t_comm = encode_string( comm, strlen(comm));
			}

		if ( strcmp(field_name, F_A0) == 0 ) {
			a0 = (char*)auparse_get_field_str(_au);
			t_a0 = encode_string( a0, strlen(a0));
			}

		if ( strcmp(field_name, F_A1) == 0 ) {
			a1 = (char*)auparse_get_field_str(_au);
			t_a1 = encode_string( a1, strlen(a1));
			}

		if ( strcmp(field_name, F_A2) == 0 ) {
			a2 = (char*)auparse_get_field_str(_au);
			t_a2 = encode_string( a2, strlen(a2));
			}


		if ( strcmp(field_name, F_PID) == 0 )
			pid = (char*)auparse_get_field_str(_au);

		if ( strcmp(field_name, F_PPID) == 0 )
			ppid = (char*)auparse_get_field_str(_au);

		if ( strcmp(field_name, F_SUCCESS) == 0 )
			success = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_EXIT) == 0 ) {
			xit = (char*)auparse_interpret_field(_au);
			t_xit = encode_string( xit, strlen(xit));
			}

		if ( strcmp(field_name, F_TTY) == 0 )
			tty = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_EXE) == 0 ) {
			exe = (char*)auparse_interpret_field(_au);
			t_exe = encode_string( exe, strlen(exe));
			}

		if ( strcmp(field_name, F_KEY) == 0 )
			key = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_SYSCALL) == 0 )
			sysc_name = (char*)auparse_interpret_field(_au);

		auparse_next_field(_au);

		}

	printf("%i:%i:%i SYSCALL_OBJ %s %u.%u %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n", *event_cnt, num_records, record_cnt, t_type, (unsigned)e->sec, e->milli, t_node, ses, auid, sysc_name, key, t_comm, t_exe, t_a0, t_a1, t_a2, uid, gid, euid, egid, fsuid, fsgid, suid, sgid, pid, ppid, tty, success, t_xit);

	strncpy(ses_holder,ses,holder_size);
	strncpy(pid_holder,pid,holder_size);

	free(t_node);
	free(t_type);
	free(t_comm);
	free(t_a0);
	free(t_a1);
	free(t_a2);
	free(t_xit);
	free(t_exe);

	return;
}

static void process_sock_obj(auparse_state_t *_au, int *event_cnt, int num_records, int record_cnt)
{
	char* type = "NULL";
	char* t_type = NULL;
	char* node = "localhost";
	char* t_node = NULL;
	char* saddr = "NULL";
	char* t_saddr = NULL;

	int num_fields = auparse_get_num_fields(_au) - 1;
	int n;

	const au_event_t *e = auparse_get_timestamp(au);
	
	if (e == NULL)
		return;

	auparse_first_field(_au);

	for ( n = 0 ; n <= num_fields; n++ ) {

		char* field_name = (char*)auparse_get_field_name(_au);

		if ( strcmp(field_name,F_TYPE) == 0 ) {
			type = (char*)auparse_interpret_field(_au);
			t_type = encode_string( type, strlen(type));
				}

		if ( strcmp(field_name, F_NODE) == 0 ) {
			node = (char*)auparse_interpret_field(_au);
			t_node = encode_string( node, strlen(node));
			}

		if ( strcmp(field_name, F_SADDR) == 0 ) {
			saddr = (char*)auparse_interpret_field(_au);
			t_saddr = encode_string( saddr, strlen(saddr));
			}

		auparse_next_field(_au);
		}

	printf("%i:%i:%i SADDR_OBJ %s %u.%u %s %s %s %s\n", *event_cnt, num_records, record_cnt, t_type, (unsigned)e->sec, e->milli, t_node, ses_holder, pid_holder, t_saddr);

	free(t_type);
	free(t_node);
	free(t_saddr);

	return;
}

static void process_execv_obj(auparse_state_t *_au, int *event_cnt, int num_records, int record_cnt)
{
	char* type = "NULL";
	char* t_type = NULL;
	char* node = "localhost";
	char* t_node = NULL;
	char* argc = "NULL";
	char* arg = "NULL";

	int num_fields = auparse_get_num_fields(_au) - 1;
	int n;

	const au_event_t *e = auparse_get_timestamp(au);
	
	if (e == NULL)
		return;

	auparse_first_field(_au);

	for ( n = 0 ; n <= num_fields; n++ ) {

		char* field_name = (char*)auparse_get_field_name(_au);

		if ( strcmp(field_name,F_TYPE) == 0 ) {
			type = (char*)auparse_interpret_field(_au);
			t_type = encode_string(type, strlen(type));
			}

		if ( strcmp(field_name, F_NODE) == 0 ) {
			node = (char*)auparse_interpret_field(_au);
			t_node = encode_string(node, strlen(node));
			}

		if ( strcmp(field_name, F_ARGC) == 0 )
			argc = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_ARG) == 0 )
			arg = (char*)auparse_interpret_field(_au);

		auparse_next_field(_au);
		}

	printf("%i:%i:%i EXEC_OBJ %s %u.%u %s %s %s %s %s\n", *event_cnt, num_records, record_cnt, t_type, (unsigned)e->sec, e->milli, t_node, ses_holder, pid_holder, argc, arg);

	free(t_type);
	free(t_node);

	return;
}

static void process_generic_obj(auparse_state_t *_au, int *event_cnt, int num_records, int record_cnt)
{

	char* type = "NULL";
	char* t_type = NULL;
	char* node = "localhost";
	char* t_node = NULL;
	char* ses = "NULL";
	char* auid = "NULL";

	char* egid = "NULL";
	char* euid = "NULL";
	char* fsgid = "NULL";
	char* fsuid = "NULL";
	char* gid = "NULL";
	char* suid = "NULL";
	char* sgid = "NULL";
	char* uid = "NULL";

	char* comm = "NULL";
	char* t_comm = NULL;
	char* exe = "NULL";
	char* t_exe = NULL;
	char* a0 = "NULL";
	char* t_a0 = NULL;
	char* a1 = "NULL";
	char* t_a1 = NULL;
	char* a2 = "NULL";
	char* t_a2 = NULL;
	char* pid = "NULL";
	char* ppid = "NULL";
	char* success = "NULL";
	char* xit = "NULL";
	char* t_xit = NULL;
	char* tty = "NULL";
	char* key = "NULL";
 
	int num_fields = auparse_get_num_fields(_au) - 1;
	int n;

	const au_event_t *e = auparse_get_timestamp(au);
	
	if (e == NULL)
		return;

	auparse_first_field(_au);

	for ( n = 0 ; n <= num_fields; n++ ) {

		char* field_name = (char*)auparse_get_field_name(_au);

		if ( strcmp(field_name,F_TYPE) == 0 ) {
			type = (char*)auparse_interpret_field(_au);
			t_type = encode_string(type, strlen(type));
			}

		if ( strcmp(field_name, F_NODE) == 0 ) {
			node = (char*)auparse_interpret_field(_au);
			t_node = encode_string(node, strlen(node));
			}

		if ( strcmp(field_name, F_SES) == 0 )
			ses = (char*)auparse_get_field_str(_au);

		if ( strcmp(field_name, F_EGID) == 0 )
			egid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_AUID) == 0 )
			auid = (char*)auparse_get_field_str(_au);

		if ( strcmp(field_name, F_EUID) == 0 )
			euid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_FSGID) == 0 )
			fsgid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_FSUID) == 0 )
			fsuid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_GID) == 0 )
			gid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_SUID) == 0 )
			suid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_SGID) == 0 )
			sgid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_UID) == 0 )
			uid = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_COMM) == 0 ) {
			comm = (char*)auparse_interpret_field(_au);
			t_comm = encode_string( comm, strlen(comm));
			}

		if ( strcmp(field_name, F_A0) == 0 ) {
			a0 = (char*)auparse_get_field_str(_au);
			t_a0 = encode_string( a0, strlen(a0));
			}

		if ( strcmp(field_name, F_A1) == 0 ) {
			a1 = (char*)auparse_get_field_str(_au);
			t_a1 = encode_string( a1, strlen(a1));
			}

		if ( strcmp(field_name, F_A2) == 0 ) {
			a2 = (char*)auparse_get_field_str(_au);
			t_a2 = encode_string( a2, strlen(a2));
			}

		if ( strcmp(field_name, F_PID) == 0 )
			pid = (char*)auparse_get_field_str(_au);

		if ( strcmp(field_name, F_PPID) == 0 )
			ppid = (char*)auparse_get_field_str(_au);

		if ( strcmp(field_name, F_SUCCESS) == 0 )
			success = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_EXIT) == 0 ) {
			xit = (char*)auparse_interpret_field(_au);
			t_xit = encode_string( xit, strlen(xit));
			}

		if ( strcmp(field_name, F_TTY) == 0 )
			tty = (char*)auparse_interpret_field(_au);

		if ( strcmp(field_name, F_EXE) == 0 ) {
			exe = (char*)auparse_interpret_field(_au);
			t_exe = encode_string( exe, strlen(exe));
			}

		if ( strcmp(field_name, F_KEY) == 0 )
			key = (char*)auparse_interpret_field(_au);

		auparse_next_field(_au);

		}

	printf("%i:%i:%i GENERIC_OBJ %s %u.%u %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n", *event_cnt, num_records, record_cnt, t_type, (unsigned)e->sec, e->milli, t_node, ses, auid, key, t_comm, t_exe, t_a0, t_a1, t_a2, uid, gid, euid, egid, fsuid, fsgid, suid, sgid, pid, ppid, tty, success, t_xit);
	//printf("%i:%i:%i GENERIC_OBJ %s %u.%u %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n", *event_cnt, num_records, record_cnt, t_type, (unsigned)e->sec, e->milli, t_node, ses, auid, key, comm, exe, a0, a1, a2, uid, gid, euid, egid, fsuid, fsgid, suid, sgid, pid, ppid, tty, success, xit);

	strncpy(ses_holder,ses,holder_size);
	strncpy(pid_holder,pid,holder_size);

	free(t_node);
	free(t_type);
	free(t_comm);
	free(t_a0);
	free(t_a1);
	free(t_a2);
	free(t_xit);
	free(t_exe);

	return;
}


/* This mess will take the generic audit identifier and provide back a 
 *  mapping to the general type that will be expected on the bro side of 
 *  things.  Kinda ugly.
 */

static int return_audtype(int rawtype)
{
	// default value
	int ret_val = GENERIC_OBJ;

	if ( rawtype == 1307 || rawtype == 1302 ) 	// CWD|PATH
		ret_val = PLACE_OBJ;

	if ( rawtype == 1300 ) 				// SYSCALL
		ret_val = SYSCALL_OBJ;

	// AUDIT_USER_AUTH, AUDIT_USER_ACCT, AUDIT_USER_MGMT, AUDIT_CRED_ACQ, AUDIT_USER_START
	// AUDIT_USER_END, AUDIT_USER_CHAUTHTOK, AUDIT_USER_ERR, AUDIT_USER_LOGIN, AUDIT_USER_LOGOUT
	// AUDIT_USER_SELINUX_ERR, AUDIT_USER_CMD
	//
	int i;
	for (i = 0; i < user_types_count; i++) {
		if ( rawtype == user_types[i] ) 
			{
			ret_val = USER_OBJ;
			break;
			}
		}

	if ( rawtype == 1306 ) 				// SOCKADDR
		ret_val = SOCK_OBJ;

	if ( rawtype == 1309 ) 				// EXECVE
		ret_val = EXECVE_OBJ;

	
	return ret_val;
}

static void auparse_callback(auparse_state_t *_au, auparse_cb_event_t cb_event_type, void *user_data)
{
        int *event_cnt = (int *)user_data;
	int num_records = auparse_get_num_records(_au);
        int record_cnt;

        if (cb_event_type == AUPARSE_CB_EVENT_READY) {
                if (auparse_first_record(_au) <= 0) {
                        printf("can't get first record\n");
                        return;
                }

                record_cnt = 1;
                do {

			int audtype = return_audtype(auparse_get_type(_au));

			switch(audtype) {
			
				case PLACE_OBJ:
					// au, event number:total rec in event:this num in event
					process_place_obj(_au, event_cnt, num_records, record_cnt);
					break;

				case USER_OBJ:
					process_user_obj(_au, event_cnt, num_records, record_cnt);
					break;

				case SYSCALL_OBJ:
					process_syscall_obj(_au, event_cnt, num_records, record_cnt);
					break;

				case SOCK_OBJ:
					process_sock_obj(_au, event_cnt, num_records, record_cnt);
					break;

				case EXECVE_OBJ:
					process_execv_obj(_au, event_cnt, num_records, record_cnt);
					break;

				case GENERIC_OBJ:
					process_generic_obj(_au, event_cnt, num_records, record_cnt);
					break;
				}

                        const au_event_t *e = auparse_get_timestamp(_au);
                        if (e == NULL) {
                                return;
                        }
                        //printf("    event time: %u.%u:%lu, host=%s\n",
                        //                (unsigned)e->sec,
                        //                e->milli, e->serial,
                        //                e->host ? e->host : "?");
                        //auparse_first_field(au);
                        //do {
                        //        printf("        %s=%s (%s)\n",
                        //                        auparse_get_field_name(au),
                       //                         auparse_get_field_str(au),
                       //                         auparse_interpret_field(au));
                        //} while (auparse_next_field(au) > 0);
                        //printf("\n");
                        record_cnt++;
                } while(auparse_next_record(_au) > 0);
                (*event_cnt)++;
        }
}


static void usage(const int status)
{
	fprintf(stdout, "Usage: %s [OPTION]... [FILE]...\n\n"
			"  -c N, --bytes=N    output the last N bytes\n"
			"  -f,   --follow     output as the file grows\n"
			"  -n N, --lines=N    output the last N lines (default: %d)\n"
			"  -v,   --verbose    print headers with file names\n"
			"  -h,   --help       show this help and exit\n"
			"  -V,   --version    show version and exit\n\n"
			"If the first character of N (the number of bytes or lines) is a `+',\n"
			"begin printing with the Nth item from the start of each file, otherwise,\n"
			"print the last N items in the file.\n", PROGRAM_NAME, DEFAULT_N_LINES);

	exit(status);
}

static inline void setup_file(struct file_struct *f)
{
	f->fd = f->i_watch = -1;
	f->size = 0;
	f->blksize = DEFAULT_BUFFER_SIZE;
	f->ignore = 0;
}

static void ignore_file(struct file_struct *f)
{
	if (f->fd != -1) {
		close(f->fd);
		f->fd = -1;
	}
	f->ignore = 1;
	n_ignored++;
}

static inline char *pretty_name(char *filename)
{
	return (strcmp(filename, "-") == 0) ? "standard input" : filename;
}

static void write_header(char *filename)
{
	static unsigned short first_file = 1;
	static char *last = NULL;

	if (last != filename) {
		fprintf(stdout, "%s==> %s <==\n", (first_file ? "" : "\n"), pretty_name(filename));
		fflush(stdout);		/* Make sure the header is printed before the content */
	}

	first_file = 0;
	last = filename;
}

static off_t lines_to_offset_from_end(struct file_struct *f, unsigned long n_lines)
{
	off_t offset = f->size;
	char *buf = emalloc(f->blksize);

	n_lines++;	/* We also count the last \n */

	while (offset > 0 && n_lines > 0) {
		int i;
		ssize_t rc, block_size = f->blksize;	/* Size of the current block we're reading */

		if (offset < block_size)
			block_size = offset;

		/* Start of current block */
		offset -= block_size;

		if (lseek(f->fd, offset, SEEK_SET) == (off_t) -1) {
			fprintf(stderr, "Error: Could not seek in file '%s' (%s)\n", f->name, strerror(errno));
			free(buf);
			return -1;
		}

		rc = read(f->fd, buf, block_size);
		if (unlikely(rc < 0)) {
			fprintf(stderr, "Error: Could not read from file '%s' (%s)\n", f->name, strerror(errno));
			free(buf);
			return -1;
		}

		for (i = block_size - 1; i > 0; i--) {
			if (buf[i] == '\n') {
				if (--n_lines == 0) {
					free(buf);
					return offset += i + 1; /* We don't want the first \n */
				}
			}
		}
	}

	free(buf);
	return offset;
}

static off_t lines_to_offset_from_begin(struct file_struct *f, unsigned long n_lines)
{
	char *buf;
	off_t offset = 0;

	/* tail everything for 'inotail -n +0' */
	if (n_lines == 0)
		return 0;

	n_lines--;
	buf = emalloc(f->blksize);

	while (offset <= f->size && n_lines > 0) {
		int i;
		ssize_t rc, block_size = f->blksize;

		if (lseek(f->fd, offset, SEEK_SET) == (off_t) -1) {
			fprintf(stderr, "Error: Could not seek in file '%s' (%s)\n", f->name, strerror(errno));
			free(buf);
			return -1;
		}

		rc = read(f->fd, buf, block_size);
		if (unlikely(rc < 0)) {
			fprintf(stderr, "Error: Could not read from file '%s' (%s)\n", f->name, strerror(errno));
			free(buf);
			return -1;
		} else if (rc < block_size)
			block_size = rc;

		for (i = 0; i < block_size; i++) {
			if (buf[i] == '\n') {
				if (--n_lines == 0) {
					free(buf);
					return offset + i + 1;
				}
			}
		}

		offset += block_size;
	}

	free(buf);
	return offset;
}

static off_t lines_to_offset(struct file_struct *f, unsigned long n_lines)
{
	if (from_begin)
		return lines_to_offset_from_begin(f, n_lines);
	else
		return lines_to_offset_from_end(f, n_lines);
}

static off_t bytes_to_offset(struct file_struct *f, unsigned long n_bytes)
{
	off_t offset = 0;

	/* tail everything for 'inotail -c +0' */
	if (from_begin) {
		if (n_bytes > 0)
			offset = (off_t) n_bytes - 1;
	} else if ((off_t) n_bytes < f->size)
		offset = f->size - (off_t) n_bytes;

	return offset;
}

static ssize_t tail_pipe(struct file_struct *f)
{
	ssize_t rc;
	char *buf = emalloc(f->blksize);

	if (verbose)
		write_header(f->name);

	/* We will just tail everything here */
	while ((rc = read(f->fd, buf, f->blksize)) > 0) {
		auparse_feed(au, buf, rc);
		if (write(STDOUT_FILENO, buf, (size_t) rc) <= 0) {
			/* e.g. when writing to a pipe which gets closed */
			fprintf(stderr, "Error: Could not write to stdout (%s)\n", strerror(errno));
			rc = -1;
			break;
		}
	}

	free(buf);
	return rc;
}

static int tail_file(struct file_struct *f, unsigned long n_units, char mode, char forever)
{
	ssize_t bytes_read = 0;
	off_t offset = 0;
	char *buf;
	struct stat finfo;

	if (strcmp(f->name, "-") == 0)
		f->fd = STDIN_FILENO;
	else {
		f->fd = open(f->name, O_RDONLY);
		if (unlikely(f->fd < 0)) {
			fprintf(stderr, "Error: Could not open file '%s' (%s)\n", f->name, strerror(errno));
			ignore_file(f);
			return -1;
		}
	}

	if (fstat(f->fd, &finfo) < 0) {
		fprintf(stderr, "Error: Could not stat file '%s' (%s)\n", f->name, strerror(errno));
		ignore_file(f);
		return -1;
	}

	if (!IS_TAILABLE(finfo.st_mode)) {
		fprintf(stderr, "Error: '%s' of unsupported file type (%s)\n", f->name, strerror(errno));
		ignore_file(f);
		return -1;
	}

	/* Cannot seek on these */
	if (IS_PIPELIKE(finfo.st_mode) || f->fd == STDIN_FILENO)
		return tail_pipe(f);

	f->size = finfo.st_size;
	f->blksize = finfo.st_blksize;	/* TODO: Can this value be 0? */

	if (mode == M_LINES)
		offset = lines_to_offset(f, n_units);
	else
		offset = bytes_to_offset(f, n_units);

	/* We only get negative offsets on errors */
	if (unlikely(offset < 0)) {
		ignore_file(f);
		return -1;
	}

	if (verbose)
		write_header(f->name);

	if (lseek(f->fd, offset, SEEK_SET) == (off_t) -1) {
		fprintf(stderr, "Error: Could not seek in file '%s' (%s)\n", f->name, strerror(errno));
		return -1;
	}

	buf = emalloc(f->blksize);

	while ((bytes_read = read(f->fd, buf, f->blksize)) > 0) {
		auparse_feed(au,buf, bytes_read);
		//write(STDOUT_FILENO, buf, (size_t) bytes_read);
		}

	if (!forever) {
		if (close(f->fd) < 0) {
			fprintf(stderr, "Error: Could not close file '%s' (%s)\n", f->name, strerror(errno));
			free(buf);
			return -1;
		}
	} /* Let the fd open otherwise, we'll need it */

	free(buf);
	return 0;
}

static int handle_inotify_event(struct inotify_event *inev, struct file_struct *f)
{
	int ret = 0;

	if (inev->mask & IN_MODIFY) {
		char *fbuf;
		ssize_t rc;
		struct stat finfo;

		if (verbose)
			write_header(f->name);

		/* Seek to old file size */
		if (lseek(f->fd, f->size, SEEK_SET) == (off_t) -1) {
			fprintf(stderr, "Error: Could not seek in file '%s' (%s)\n", f->name, strerror(errno));
			ret = -1;
			goto ignore;
		}

		fbuf = emalloc(f->blksize);

		while ((rc = read(f->fd, fbuf, f->blksize)) != 0) {
			auparse_feed(au,fbuf, rc);
			write(STDOUT_FILENO, fbuf, (size_t) rc);
			}

		if (fstat(f->fd, &finfo) < 0) {
			fprintf(stderr, "Error: Could not stat file '%s' (%s)\n", f->name, strerror(errno));
			ret = -1;
			free(fbuf);
			goto ignore;
		}

		f->size = finfo.st_size;

		free(fbuf);
		return ret;
	} else if (inev->mask & IN_DELETE_SELF) {
		fprintf(stderr, "File '%s' deleted.\n", f->name);
	} else if (inev->mask & IN_MOVE_SELF) {
		fprintf(stderr, "File '%s' moved.\n", f->name);
		return 0;
	} else if (inev->mask & IN_UNMOUNT) {
		fprintf(stderr, "Device containing file '%s' unmounted.\n", f->name);
	}

ignore:
	ignore_file(f);
	return ret;
}

static int watch_files(struct file_struct *files, int n_files)
{
	int ifd, i;
	char buf[n_files * INOTIFY_BUFLEN];

	ifd = inotify_init();
	if (errno == ENOSYS) {
		fprintf(stderr, "Error: inotify is not supported by the kernel you're currently running.\n");
		exit(EXIT_FAILURE);
	} else if (unlikely(ifd < 0)) {
		fprintf(stderr, "Error: Could not initialize inotify (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < n_files; i++) {
		if (!files[i].ignore) {
			files[i].i_watch = inotify_add_watch(ifd, files[i].name,
						IN_MODIFY|IN_DELETE_SELF|IN_MOVE_SELF|IN_UNMOUNT);

			if (files[i].i_watch < 0) {
				fprintf(stderr, "Error: Could not create inotify watch on file '%s' (%s)\n",
						files[i].name, strerror(errno));
				ignore_file(&files[i]);
			}
		}
	}

	while (n_ignored < n_files) {
		ssize_t len;
		int ev_idx = 0;

		len = read(ifd, buf, (n_files * INOTIFY_BUFLEN));
		if (unlikely(len < 0)) {
			/* Some signal, likely ^Z/fg's STOP and CONT interrupted the inotify read, retry */
			if (errno == EINTR || errno == EAGAIN)
				continue;
			else {
				fprintf(stderr, "Error: Could not read inotify events (%s)\n", strerror(errno));
				exit(EXIT_FAILURE);
			}
		}

		while (ev_idx < len) {
			struct inotify_event *inev;
			struct file_struct *f = NULL;

			inev = (struct inotify_event *) &buf[ev_idx];

			/* Which file has produced the event? */
			for (i = 0; i < n_files; i++) {
				if (!files[i].ignore
						&& files[i].fd >= 0
						&& files[i].i_watch == inev->wd) {
					f = &files[i];
					break;
				}
			}

			if (unlikely(!f))
				break;

			if (handle_inotify_event(inev, f) < 0)
				break;

			ev_idx += sizeof(struct inotify_event) + inev->len;
		}
	}

	close(ifd);
	return -1;
}

int main(int argc, char **argv)
{
	int i, c, ret = 0;
	int n_files;
	unsigned long n_units = DEFAULT_N_LINES;
	char forever = 0, mode = M_LINES;
	char **filenames;
	struct file_struct *files = NULL;
	int event_cnt = 1;

	au = auparse_init(AUSOURCE_FEED, 0);
	auparse_add_callback(au, auparse_callback, &event_cnt, NULL);

	if (au == NULL) {
		printf("Error - %s\n", strerror(errno));
		return 1;
	}

	while ((c = getopt_long(argc, argv, "c:n:fvVh", long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			mode = M_BYTES;
			/* fall through */
		case 'n':
			if (*optarg == '+') {
				from_begin = 1;
				optarg++;
			} else if (*optarg == '-')
				optarg++;

			if (!is_digit(*optarg)) {
				fprintf(stderr, "Error: Invalid number of units: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			n_units = strtoul(optarg, NULL, 0);
			break;
                case 'f':
			forever = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'V':
			fprintf(stdout, "%s %s\n", PROGRAM_NAME, VERSION);
			exit(EXIT_SUCCESS);
		case 'h':
			usage(EXIT_SUCCESS);
		default:
			usage(EXIT_FAILURE);
		}
	}

	/* Do we have some files to read from? */
	if (optind < argc) {
		n_files = argc - optind;
		filenames = argv + optind;
	} else {
		/* It must be stdin then */
		static char *dummy_stdin = "-";
		n_files = 1;
		filenames = &dummy_stdin;

		/* POSIX says that -f is ignored if no file operand is
		   specified and standard input is a pipe. */
		if (forever) {
			struct stat finfo;
			int rc = fstat(STDIN_FILENO, &finfo);

			if (unlikely(rc == -1)) {
				fprintf(stderr, "Error: Could not stat stdin (%s)\n", strerror(errno));
				exit(EXIT_FAILURE);
			}

			if (rc == 0 && IS_PIPELIKE(finfo.st_mode))
				forever = 0;
		}
	}

	files = emalloc(n_files * sizeof(struct file_struct));

	for (i = 0; i < n_files; i++) {
		files[i].name = filenames[i];
		setup_file(&files[i]);
		ret = tail_file(&files[i], n_units, mode, forever);
		if (ret < 0)
			ignore_file(&files[i]);
	}

	if (forever)
		ret = watch_files(files, n_files);

	free(files);

	auparse_flush_feed(au);
	auparse_destroy(au);

	return ret;
}
