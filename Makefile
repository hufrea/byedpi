TARGET = ciadpi
CC ?= gcc
CFLAGS += -std=c99 -O2 -D_XOPEN_SOURCE=500 
SOURCES = packets.c main.c conev.c proxy.c desync.c error.c

all:
	$(CC) $(CFLAGS) $(SOURCES) -I . -o $(TARGET)

windows:
	$(CC) $(CFLAGS) $(SOURCES) -I . -lws2_32 -o $(TARGET).exe

clean:
	rm -f $(TARGET) *.o
