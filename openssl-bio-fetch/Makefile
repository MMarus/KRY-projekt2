# Default rule
default: openssl-bio-fetch.exe

CC=gcc
# Debug or Release
CONFIG = -g3 -ggdb -O0 -DDEBUG=1
# CONFIG = -g2 -Os -DNDEBUG=1

OUR_CFLAGS = $(CONFIG) -std=c99 -Wall -Wextra -Wconversion -Wformat -Wformat=2 -Wformat-security -Wno-deprecated-declarations -Wno-unused-function

# Clear unneeded implicit rules
.SUFFIXES:
.SUFFIXES: .c

SOURCES = openssl-bio-fetch.c
OBJECTS = $(SOURCES:.=.o)
OUTPUT = openssl-bio-fetch.exe
CCTLD = cctld.txt

# Standard OpenSSL include directory
OPENSSL_LDFLAGS = -lssl -lcrypto
# Merge our flags with user's flags
override CPPFLAGS := $(OUR_CPPFLAGS) $(CPPFLAGS)
override CFLAGS := $(OUR_CFLAGS) $(CFLAGS)
override LDFLAGS := $(OUR_LDFLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS)

$(OUTPUT): openssl-bio-fetch.h openssl-bio-fetch.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(OPENSSL_INCLUDE) $(SOURCES) -o $(OUTPUT) $(LDFLAGS)

.PHONY: clean
clean:
	-rm -rf $(OUTPUT) core *.core *.dSYM *.tmp .DS_Store
