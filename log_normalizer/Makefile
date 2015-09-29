# Makefile for auditparse
#
# Copyright (C) 2006-2007 Tobias Klauser <tklauser@distanz.ch>
#
# Licensed under the terms of the GNU General Public License; version 2 or later.

VERSION	= 0.5

# Paths
prefix	= /usr/local
BINDIR	= $(prefix)/bin
MANDIR	= $(prefix)/share/man/man1

CC	:= gcc -laudit  -lauparse
CFLAGS	:= $(CFLAGS) -pipe -D_USE_SOURCE -DVERSION="\"$(VERSION)\"" -W -Wall \
	   -Wstrict-prototypes -Wsign-compare -Wshadow -Wchar-subscripts \
	   -Wmissing-declarations -Wpointer-arith -Wcast-align -Wmissing-prototypes -laudit  -lauparse

# Compile with 'make DEBUG=true' to enable debugging
DEBUG = false
ifeq ($(strip $(DEBUG)),true)
	CFLAGS  += -g -DDEBUG
endif

all: auditparse
auditparse: auditparse.o modp_burl.o
modp_burl: modp_burl.o

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

install: auditparse
	install -m 775 -D auditparse $(BINDIR)/auditparse
	install -m 644 -D auditparse.1 $(MANDIR)/auditparse
	gzip -9 $(MANDIR)/auditparse.1

uninstall:
	rm $(BINDIR)/auditparse $(MANDIR)/auditparse.1*

cscope:
	cscope -b

release:
	git-archive --format=tar --prefix=auditparse-$(VERSION)/ HEAD | gzip -9v > ../auditparse-$(VERSION).tar.gz
	git-archive --format=tar --prefix=auditparse-$(VERSION)/ HEAD | bzip2 -9v > ../auditparse-$(VERSION).tar.bz2

clean:
	rm -f auditparse *.o cscope.*
