
AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -DVERSION=\"$(VERSION)\" -DPROG="\"$(PACKAGE)\"" -D_FILE_OFFSET_BITS=64 \
	-D_BSD_SOURCE \
	-I$(top_srcdir)/src \
	-DKL_USERSPACE
AM_CFLAGS = -Wall -O3

LDADD = ../src/libklscte35.la -lklvanc

if DEBUG
	CFLAGS += -g
endif

CXXFLAGS = $(CFLAGS)

SRC  = klscte35_util.c
SRC += demo.c
SRC += parse.c
SRC += scte104.c
SRC += scte104to35.c

bin_PROGRAMS  = klscte35_util
bin_PROGRAMS += klscte35_parse
bin_PROGRAMS += klscte35_scte104
bin_PROGRAMS += klscte35_scte104to35

klscte35_util_SOURCES = $(SRC)
klscte35_parse_SOURCES = $(SRC)
klscte35_scte104_SOURCES = $(SRC)
klscte35_scte104to35_SOURCES = $(SRC)


