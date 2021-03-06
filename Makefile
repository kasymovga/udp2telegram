CC=gcc
CFLAGS=-O2 -Wall -std=c99
CFLAGS_BASE=$(CFLAGS) `pkg-config --cflags libcurl` `pkg-config --cflags json-c`
LDFLAGS=
LDFLAGS_BASE=$(LDFLAGS) `pkg-config --libs libcurl` `pkg-config --libs json-c`
COMP=$(CC) -c $(CFLAGS_BASE) -o
LINK=$(CC) -o

.PHONY: all

all: udpchat

main.o : main.c
	$(COMP) $@ $<

udpchat: main.o
	$(LINK) $@ $^ $(LDFLAGS_BASE)
