
AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libklscte35.la

libklscte35_la_SOURCES  = scte35.c
libklscte35_la_SOURCES += scte35-to104.c
libklscte35_la_SOURCES += scte35-from104.c
libklscte35_la_SOURCES += crc32.c
libklscte35_la_SOURCES += crc32.h
libklscte35_la_SOURCES += klbitstream_readwriter.h
if USE_LIBJSONC
libklscte35_la_SOURCES += scte35-tojson.c
else
libklscte35_la_SOURCES += scte35-tojson-stub.c
endif

libklscte35_la_CFLAGS = -Wall -DVERSION=\"$(VERSION)\" -DPROG="\"$(PACKAGE)\"" \
	-D_FILE_OFFSET_BITS=64 -O3 --std=c99 -D_BSD_SOURCE \
	-DKL_USERSPACE

if DEBUG
  libklscte35_la_CFLAGS += -g
endif

libklscte35_includedir = $(includedir)/libklscte35

libklscte35_include_HEADERS  = libklscte35/scte35.h

