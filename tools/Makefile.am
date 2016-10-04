
AUTOMAKE_OPTIONS = foreign

CFLAGS = -Wall -DVERSION=\"$(VERSION)\" -DPROG="\"$(PACKAGE)\"" -D_FILE_OFFSET_BITS=64 -O3 \
	-D_BSD_SOURCE \
	--std=c99 \
	-I../src \
	-L../src/.libs -lklscte35 -lpthread \
	-DKL_USERSPACE -lz -ldl -lklscte35

if DEBUG
	CFLAGS += -g
endif

CXXFLAGS = $(CFLAGS)

SRC  = klscte35_util.c
SRC += demo.c
SRC += parse.c
SRC += scte104.c

bin_PROGRAMS  = klscte35_util
bin_PROGRAMS += klscte35_parse
bin_PROGRAMS += klscte35_scte104

klscte35_util_SOURCES = $(SRC)
klscte35_parse_SOURCES = $(SRC)
klscte35_scte104_SOURCES = $(SRC)


