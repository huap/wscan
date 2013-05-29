all: wscan

CC 	= gcc
CFLAGS 	= -static -O2 -g

.c.o:	$(CC) $(CFLAGS) \
	-c -o $*.o $<
OBJS = wscan.o scan_engine.o tcp_scan.o socks5.o socket.o
	
wscan: $(OBJS)
	$(CC) -o wscan $(OBJS) -static -g  -lpthread
	
clean:
	rm -f wscan *.o
