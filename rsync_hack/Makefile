LDFLAGS=-shared -nostdlib
LDLIBS=-lc -ldl
CFLAGS=-fPIC -Wall -g -D_REENTRANT

%.so: %.o
	gcc -o $@ $(LDFLAGS) $< $(LDLIBS)

all: rsync_hack.so
