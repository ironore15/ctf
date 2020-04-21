CC= gcc
CFLAGS= -g -Wall -I/usr/include/lua5.3 -L/usr/lib -llua5.3
LDLIBS+= -L/usr/lib -llua5.3

.PHONY: all clean

all: stegasaurus tries

clean:
	rm -rf stegasaurus tries

stegasaurus: stegasaurus.c

tries:
	mkdir tries

