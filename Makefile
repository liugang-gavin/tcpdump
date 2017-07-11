CC=gcc

CSRC = tcpdump.c ieee80211.c cpack.c

OBJ = $(CSRC:.c=.o)

CFLAGS = -g -O2

LIBS = -lpcap

PROC = mydump

all : clean $(PROC)

$(PROC):$(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LIBS)
clean:
	rm -f $(OBJ) $(PROC)
