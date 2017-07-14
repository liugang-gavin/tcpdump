CC=gcc

CSRC = tcpdump.c ieee80211.c cpack.c decoder.c
OBJ  = $(CSRC:.c=.o)
LIBS = -lpcap -lpthread
PROC = mydump
CFLAGS = -g -O2


SENDCSRC = sendconnect.c
SENDOBJ  = $(SENDCSRC:.c=.o)
SENDLIBS =
SENDPROC = sendconnect


all : clean $(PROC) $(SENDPROC)

$(PROC):$(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LIBS)

$(SENDPROC):$(SENDOBJ)
	$(CC) $(CFLAGS) $(SENDOBJ) -o $@ $(SENDLIBS)

clean:
	rm -f $(OBJ) $(PROC) $(SENDOBJ) $(SENDPROC)
