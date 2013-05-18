PROTOC = protoc --cpp_out=.
CC = g++ -c -fPIC -lprotobuf

protobuf_compile: protobuf_gen
	$(CC) vhsm_transport.pb.cc

protobuf_gen: vhsm_transport.proto
	$(PROTOC) vhsm_transport.proto

clean:
	rm -f *.o *~ *.out *.pb.cc *.pb.h
