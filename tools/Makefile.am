
AUTOMAKE_OPTIONS = foreign

CFLAGS = -Wall -DVERSION=\"$(VERSION)\" -DPROG="\"$(PACKAGE)\"" -D_FILE_OFFSET_BITS=64 -O3 \
	-D_BSD_SOURCE \
	--std=c99 \
	-I../src -I/usr/local/include \
	-L../src/.libs -lklscte35 -lpthread \
	-DKL_USERSPACE -L/usr/local/lib -lz -ldl -lklscte35

if DEBUG
	CFLAGS += -g
endif

CXXFLAGS = $(CFLAGS)

SRC  = klscte35_util.c
SRC += demo.c
SRC += parse.c

bin_PROGRAMS  = klscte35_util
bin_PROGRAMS += klscte35_parse

klscte35_util_SOURCES = $(SRC)
klscte35_parse_SOURCES = $(SRC)

