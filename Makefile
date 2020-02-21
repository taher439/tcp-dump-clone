CC=gcc
CFLAGS= -W -Wall -Wextra -O2 -g -D SUPPORT_DHCP -w
LIBS= -lpcap

SRC=$(wildcard *.c)
OBJS=$(SRC:.c=.o)
AOUT=main

all: main clean_obj

main : $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< $(LIBS)

clean_obj:
	@rm *.o

clean:
	@rm $(AOUT)
