TARGET = ciadpi
CC ?= gcc
CFLAGS += -std=c99 -O2 -D_XOPEN_SOURCE=500 
SOURCES = packets.c main.c conev.c proxy.c desync.c

all:
	$(CC) $(CFLAGS) $(SOURCES) -I . -o $(TARGET)

clean:
	rm -f $(TARGET) *.o
