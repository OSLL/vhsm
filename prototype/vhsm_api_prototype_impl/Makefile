CC = g++ -I.. -c
LD = ld

OBJECTS = common_impl.o digest_impl.o mac_impl.o

all: common digest mac
	$(LD) -o vhsm_api_prototype_impl.o $(OBJECTS)

common: common_impl.c
	$(CC) common_impl.c

digest: digest_impl.c
	$(CC) digest_impl.c

mac: mac_impl.c
	$(CC) mac_impl.c

clean:
	rm -f *.o *~ *.out
