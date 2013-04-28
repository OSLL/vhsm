CC = g++ -I.. -c
LD = ld
PROTOC = protoc --cpp_out=.

OBJECTS = common_impl.o digest_impl.o mac_impl.o

all: common digest mac
	$(LD) -o vhsm_api_prototype_impl.o $(OBJECTS)

common: common_impl.c
	$(CC) common_impl.c

digest: digest_impl.c
	$(CC) digest_impl.c

mac: mac_impl.c
	$(CC) mac_impl.c

transport: transport_proto transport_impl.cpp
	$(CC) transport_impl.cpp vhsm_transport.pb.cc

transport_proto: vhsm_transport.proto
	$(PROTOC) vhsm_transport.proto

clean:
	rm -f *.o *~ *.out *.pb.cc *.pb.h
