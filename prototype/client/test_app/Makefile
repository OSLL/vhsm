CC = g++ -I../vhsm_api_prototype

all: utils test_digest test_create_key test_hmac test_gen_keys test_enum_keys

utils: utils.h utils.cpp
	$(CC) -c utils.cpp

test_digest: utils.h test_digest.cpp utils.o
	$(CC) utils.o test_digest.cpp ../vhsm_api_prototype_impl/vhsm_api.a -o test_digest -lprotobuf -lpthread

test_create_key: utils.h test_create_key.cpp utils.o
	$(CC)  utils.o test_create_key.cpp ../vhsm_api_prototype_impl/vhsm_api.a -o test_create_key -lprotobuf -lpthread
  
test_hmac: utils.h test_create_key.cpp utils.o
	$(CC) utils.o test_hmac.cpp ../vhsm_api_prototype_impl/vhsm_api.a -o test_hmac -lprotobuf -lpthread 

test_gen_keys: utils.h test_gen_keys.cpp utils.o
	$(CC) utils.o test_gen_keys.cpp ../vhsm_api_prototype_impl/vhsm_api.a -o test_gen_keys -lprotobuf -lpthread

test_enum_keys: utils.h test_enum_keys.cpp utils.o
	$(CC) utils.o test_enum_keys.cpp ../vhsm_api_prototype_impl/vhsm_api.a -o test_enum_keys -lprotobuf -lpthread

clean:
	rm *~ *.out *.o test_digest test_create_key test_hmac test_gen_keys test_enum_keys -f
