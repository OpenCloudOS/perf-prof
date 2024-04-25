CC=gcc

CFLAGS=-Wall -g -O2

SRCS=pthread.c

CFLAGS_pthread=-lpthread

OBJS=$(SRCS:.c=.o)

BINS=$(SRCS:.c=)

all: $(BINS)

%: %.c
	$(CC) $(CFLAGS) $(CFLAGS_$@) -o $@ $<

clean:
	rm -f $(OBJS) $(BINS)