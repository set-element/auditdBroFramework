/*
 * Copyright (C) 2005-2007, Tobias Klauser <tklauser@distanz.ch>
 *
 * Licensed under the terms of the GNU General Public License; version 2 or later.
 */

#ifndef _INOTAIL_H
#define _INOTAIL_H

#include <sys/types.h>

/* Number of items to tail. */
#define DEFAULT_N_LINES 10

/* tail modes */
enum { M_LINES, M_BYTES };

/* Every tailed file is represented as a file_struct */
struct file_struct {
	char *name;		/* Name of file (or '-' for stdin) */
	int fd;			/* File descriptor (or -1 if file is not open */
	off_t size;		/* File size */
	blksize_t blksize;	/* Blocksize for filesystem I/O */
	unsigned ignore;	/* Whether to ignore the file in further processing */
	int i_watch;		/* Inotify watch associated with file_struct */
};

#define PLACE_OBJ 1
#define USER_OBJ  2
#define SYSCALL_OBJ 3 
#define SOCK_OBJ 4 
#define EXECVE_OBJ 5 
#define GENERIC_OBJ 6

int user_types[] = {1100, 1101, 1102, 1103, 1105, 1106, 1108, 1109, 1112, 1113, 1122, 1123};
int user_types_count = 12;
#define F_A0 "a0"
#define F_A1 "a1"
#define F_A2 "a2"
#define F_ARG "arg"
#define F_ARGC "argc"
#define F_AUID "auid"
#define F_COMM "comm"
#define F_CWD "cwd"
#define F_EGID "egid"
#define F_EUID "euid"
#define F_EXE "exe"
#define F_EXIT "exit"
#define F_FLAVOR "flavor"
#define F_FSGID "fsgid"
#define F_FSUID "fsuid"
#define F_GID "gid"
#define F_INODE "inode"
#define F_HEY "key"
#define F_MODE "mode"
#define F_MSG "msg"
#define F_NAME "name"
#define F_NODE "node"
#define F_AGID "ogid"
#define F_PID "pid"
#define F_PPID "ppid"
#define F_SADDR "saddr"
#define F_SES "ses"
#define F_SGID "sgid"
#define F_SUCCESS "success"
#define F_SUID "suid"
#define F_SYSCALL "syscall"
#define F_TERMINAL "terminal"
#define F_TIME "time"
#define F_TTY "tty"
#define F_TYPE "type"
#define F_UID "uid"
#define F_FLAVOR "flavor"
#define F_OUID "ouid"
#define F_OGID "ogid"
#define F_TERM "terminal"
#define F_KEY "key"

#define IS_PIPELIKE(mode) \
	(S_ISFIFO(mode) || S_ISSOCK(mode))

/* inotail works on these file types */
#define IS_TAILABLE(mode) \
	(S_ISREG(mode) || IS_PIPELIKE(mode) || S_ISCHR(mode))

#define is_digit(c) ((c) >= '0' && (c) <= '9')

#ifdef DEBUG
# define dprintf(fmt, args...) fprintf(stderr, fmt, ##args)
#else
# define dprintf(fmt, args...)
#endif /* DEBUG */

#ifdef __GNUC__
# define unlikely(x) __builtin_expect(!!(x), 0)
#else
# define unlikely(x) (x)
#endif /* __GNUC__ */

#endif /* _INOTAIL_H */
