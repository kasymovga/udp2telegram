CC=gcc
CFLAGS=-O2
CFLAGS_BASE=$(CFLAGS) `pkg-config --cflags libcurl` `pkg-config --cflags json-c`
LDFLAGS=
LDFLAGS_BASE=$(LDFLAGS) `pkg-config --libs libcurl` `pkg-config --libs json-c`
COMP=$(CC) -c $(CFLAGS_BASE) -o
LINK=$(CC) $(LDFLAGS_BASE) -o

.PHONY: all

all: udpchat

main.o : main.c
	$(COMP) $@ $<

udpchat: main.o
	$(LINK) $@ $^
