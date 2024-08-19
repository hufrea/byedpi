TARGET = ciadpi

CPPFLAGS = -D_DEFAULT_SOURCE
CFLAGS += -I. -std=c99 -Wall -Wno-unused -O2
WIN_LDFLAGS = -lws2_32 -lmswsock

SRC = packets.c main.c conev.c proxy.c desync.c mpool.c extend.c
WIN_SRC = win_service.c

OBJ = $(SRC:.c=.o)
WIN_OBJ = $(WIN_SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $(TARGET) $(OBJ) $(LDFLAGS)

windows: $(OBJ) $(WIN_OBJ)
	$(CC) -o $(TARGET).exe $(OBJ) $(WIN_OBJ) $(WIN_LDFLAGS)

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

clean:
	rm -f $(TARGET) $(TARGET).exe $(OBJ) $(WIN_OBJ)
