all: test_engine

test_engine: main.c
	g++ -c -ggdb3 -I.. -fPIC main.c
	g++ -shared -ggdb3 -fPIC main.o ../vhsm_api_prototype_impl/common_impl.o ../vhsm_api_prototype_impl/digest_impl.o ../vhsm_api_prototype_impl/mac_impl.o ../vhsm_api_prototype_impl/transport_impl.o ../../protocol/vhsm_transport.pb.o  -o test_engine.so -lprotobuf -lcrypto -lssl -ldl
clean:
	rm -f *.o *.so
