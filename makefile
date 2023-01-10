LDLIBS=-lpcap -lpthread

all: airodump

airodump: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@
	rm -f *.o

clean:
	rm -f airodump *.o
