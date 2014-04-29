# Makefile for linux "page fault test"
#
#

# until this shows up in distro headers
# pft will check whether or not kernel supports it.
RUSAGE_THREAD ?= -DUSE_RUSAGE_THREAD

# Requires kernel patch to work.
NOCLEAR       ?= -UUSE_NOCLEAR

#--------------------------------------------
SHELL   = /bin/sh

MACH    =

CMODE	= -std=gnu99
COPT	= $(CMODE) -pthread -O3 #-non_shared
DEFS    = -D_GNU_SOURCE $(RUSAGE_THREAD) $(NOCLEAR)
INCLS   =  #-I
CFLAGS  = $(COPT) $(DEFS) $(INCLS) $(ECFLAGS)

LDOPTS	= #-dnon_shared
# comment out '-lnuma' for platforms w/o libnuma -- laptops?
LDLIBS	= -lpthread -lrt -lnuma
LDFLAGS = $(CMODE) $(LDOPTS) $(ELDFLAGS)

HDRS    =

OBJS    = pft.o

EXTRAHDRS =

# Include 'numa_stubs.o' for platforms w/o libnuma -- laptops?
EXTRAOBJS = /usr/include/numa.h /usr/include/numaif.h

PROGS	= pft

PROJ	= pft

#---------------------------------

all:    $(PROGS)

pft:  $(OBJS) $(EXTRAOBJS)
	$(CC) -o $@ $(LDFLAGS) $(OBJS) $(EXTRAOBJS) $(LDLIBS)

$(OBJS):    $(HDRS)

# extra dependencies to generate errors if headers are missing
pft.o:

install:
	@echo "install not implemented"

clean:
	-rm -f *.o core.[0-9]* Log*

clobber: clean
	-rm -f  $(PROGS) cscope.*

# ------------------------------------------------
# N.B., renames current directory to new version name!
# [and, yes, this is really ugly...]
VERSION=$$(cat $$_WD/version.h|grep _VERSION|sed 's/^.* "\([0-9.a-z+-]*\)".*$$/\1/')
tarball:  clobber
	@chmod --recursive u+r .pc; \
	_WD=`pwd`; _WD=`basename $$_WD`; cd ..;\
	_version=$(VERSION); _tarball=$(PROJ)-$${_version}.tar.gz; \
	_newWD=`echo $$_WD | sed  s:-.*:-$$_version:`; \
	if [ "$$_WD" != "$$_newWD" ] ; then \
		echo "Renaming '.' [$$_WD/] to $$_newWD/"; \
		mv $$_WD $$_newWD; \
	fi ; \
	tar czf - $$_newWD  >$$_tarball; \
	if [ $$? -eq 0 ]; then \
		echo "tarball at ../$$_tarball"; \
	else \
		echo "Error making tarball"; \
	fi
