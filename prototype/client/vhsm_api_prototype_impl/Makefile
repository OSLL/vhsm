CC = g++ -I.. -I../../protocol -I../../files_transport/ -I../../netlink_transport
AR = ar crf

OBJECTS = common_impl.o digest_impl.o mac_impl.o key_mgmt_impl.o transport_impl.o ../../protocol/vhsm_transport.pb.o ../../netlink_transport/VhsmMessageTransport.o

static_lib: transport common digest mac key_mgmt
	$(AR) vhsm_api.a $(OBJECTS)

common: common_impl.c
	$(CC) -c -fPIC common_impl.c

digest: digest_impl.c
	$(CC) -c -fPIC digest_impl.c

mac: mac_impl.c
	$(CC) -c -fPIC mac_impl.c

key_mgmt: key_mgmt_impl.c
	$(CC) -c -fPIC key_mgmt_impl.c

transport: transport_impl.cpp
	$(CC) -c -fPIC transport_impl.cpp

clean:
	rm -f *.o *~ *.out *.pb.cc *.pb.h *.a
