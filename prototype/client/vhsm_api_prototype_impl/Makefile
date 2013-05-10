CC = g++ -I.. -I../../protocol -I../../files_transport/
AR = ar crf

OBJECTS = common_impl.o digest_impl.o mac_impl.o transport_impl.o ../../protocol/vhsm_transport.pb.o

static_lib: transport common digest mac
	$(AR) vhsm_api.a $(OBJECTS)

common: common_impl.c
	$(CC) -c common_impl.c

digest: digest_impl.c
	$(CC) -c digest_impl.c

mac: mac_impl.c
	$(CC) -c mac_impl.c

transport: transport_impl.cpp
	$(CC) -c transport_impl.cpp

clean:
	rm -f *.o *~ *.out *.pb.cc *.pb.h *.a
