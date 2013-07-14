all: test_engine test_app

test_engine: main.c
	g++ -c -ggdb3 -I.. -fPIC main.c
	g++ -shared -ggdb3 -fPIC main.o ../vhsm_api_prototype_impl/common_impl.o ../vhsm_api_prototype_impl/digest_impl.o ../vhsm_api_prototype_impl/mac_impl.o ../vhsm_api_prototype_impl/transport_impl.o ../../protocol/vhsm_transport.pb.o  -o test_engine.so -lprotobuf -lcrypto -lssl -ldl

test_app: test_app.c
	gcc -std=c99 -o e_test_app test_app.c -lcrypto -lssl -ldl	
	
clean:
	rm -f e_test_app *.o *.so
