# Public review build: compiles library only; no key generation or secret logging by default.
CC ?= cc
AR ?= ar
CFLAGS ?= -O2 -Wall -Wextra -std=c99
CPPFLAGS ?=
LDLIBS ?= -lcrypto
SOURCES = address.c rng.c wots.c utils.c fors.c sign.c hash_sha256.c thash_sha256_simple.c logger.c sha256.c
OBJECTS = $(SOURCES:.c=.o)
.PHONY: all clean
all: libfors_research.a
libfors_research.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)
%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
clean:
	rm -f $(OBJECTS) libfors_research.a
# Explicitly opt in to raw-secret logging only with synthetic test keys:
# make clean && make CPPFLAGS=-DENABLE_CPA_LOGGING
