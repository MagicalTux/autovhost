#!/bin/make

CC=gcc
CFLAGS=-Wall --std=gnu99 -pipe -O0 -g -ggdb
TARGETS=transmit_daemon

all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	$(RM) $(TARGETS)

