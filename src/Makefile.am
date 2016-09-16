
AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libklscte35.la

libklscte35_la_SOURCES  = scte35.c

libklscte35_la_CFLAGS = -Wall -DVERSION=\"$(VERSION)\" -DPROG="\"$(PACKAGE)\"" \
	-D_FILE_OFFSET_BITS=64 -O3 --std=c99 -D_BSD_SOURCE -I../include -I/usr/local/include \
	-DKL_USERSPACE -L/usr/local/lib

if DEBUG
  libklscte35_la_CFLAGS += -g
endif

libklscte35_includedir = $(includedir)/libklscte35

libklscte35_include_HEADERS  = libklscte35/scte35.h

