TARGET = ciadpi

CPPFLAGS = -D_DEFAULT_SOURCE
CFLAGS += -I. -std=c99 -Wall -Wno-unused -O2
WIN_LDFLAGS = -lws2_32 -lmswsock

SRC = packets.c main.c conev.c proxy.c desync.c mpool.c extend.c
WIN_SRC = win_service.c

PREFIX := /usr/local
INSTALL_DIR := $(DESTDIR)$(PREFIX)/bin/

all: 
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

windows: 
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SRC) $(WIN_SRC) -o $(TARGET).exe $(WIN_LDFLAGS)

clean:
	rm -f $(TARGET) $(TARGET).exe $(OBJ) $(WIN_OBJ)

install: all
	mkdir -p $(INSTALL_DIR)
	install -m 755 $(TARGET) $(INSTALL_DIR)
