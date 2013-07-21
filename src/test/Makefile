CC = g++ -I../client/vhsm_api_prototype
API_LIB = ../client/vhsm_api_prototype_impl/vhsm_api.a
LIBS = -lprotobuf -lpthread

all: utils test_digest test_create_key test_hmac test_gen_keys test_enum_keys unit_test

utils: utils.h utils.cpp
	$(CC) -c utils.cpp

test_digest: utils.h test_digest.cpp utils.o
	$(CC) utils.o test_digest.cpp $(API_LIB) -o test_digest $(LIBS)

test_create_key: utils.h test_create_key.cpp utils.o
	$(CC)  utils.o test_create_key.cpp $(API_LIB) -o test_create_key $(LIBS)
  
test_hmac: utils.h test_create_key.cpp utils.o
	$(CC) utils.o test_hmac.cpp $(API_LIB) -o test_hmac $(LIBS)

test_gen_keys: utils.h test_gen_keys.cpp utils.o
	$(CC) utils.o test_gen_keys.cpp $(API_LIB) -o test_gen_keys $(LIBS)

test_enum_keys: utils.h test_enum_keys.cpp utils.o
	$(CC) utils.o test_enum_keys.cpp $(API_LIB) -o test_enum_keys $(LIBS)

unit_test:
	$(MAKE) -C unit_tests

clean:
	rm *~ *.out *.o test_digest test_create_key test_hmac test_gen_keys test_enum_keys -f
	$(MAKE) -C unit_tests clean
