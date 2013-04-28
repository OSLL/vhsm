CC = g++ -I..
PROTOC = protoc --cpp_out=.

OBJECTS = common_impl.o digest_impl.o mac_impl.o transport_impl.o vhsm_transport.pb.o

all: common digest mac
	$(CC) -o vhsm_api_prototype_impl.o $(OBJECTS) -lprotobuf

common: common_impl.c
	$(CC) -c common_impl.c

digest: digest_impl.c
	$(CC) -c digest_impl.c

mac: mac_impl.c
	$(CC) -c mac_impl.c

transport: transport_proto transport_impl.cpp
	$(CC) -c transport_impl.cpp

transport_proto: vhsm_transport.proto
	$(PROTOC) vhsm_transport.proto
	$(CC) -c vhsm_transport.pb.cc

clean:
	rm -f *.o *~ *.out *.pb.cc *.pb.h
