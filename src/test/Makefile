CC = g++ -I../client
API_LIB = ../client/vhsm_api_prototype_impl/vhsm_api.a
LIBS = -lprotobuf -lpthread -lcppunit -lcryptopp

all: build_unit_tests test_login test_key_mgmt test_digest test_hmac

build_unit_tests: 
	$(MAKE) -C unit_tests

test_login: test_login.cpp
	$(CC) test_login.cpp $(API_LIB) -o test_login $(LIBS)

test_key_mgmt: test_key_mgmt.cpp
	$(CC) test_key_mgmt.cpp $(API_LIB) -o test_key_mgmt $(LIBS)

test_digest: test_digest.cpp
	${CC} test_digest.cpp $(API_LIB) -o test_digest $(LIBS)
  
test_hmac: test_hmac.cpp
	$(CC) test_hmac.cpp $(API_LIB) -o test_hmac $(LIBS)

clean:
	$(MAKE) -C unit_tests clean
	rm *~ *.out *.o test_login test_key_mgmt test_hmac -f

