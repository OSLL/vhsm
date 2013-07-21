CC = g++ -I../../vhsm -I../../protocol -I../../netlink_transport
LIBS = -lpthread -lprotobuf -lcryptopp -lsqlite3 -lcppunit

MH_OBJECTS = ../../vhsm/VhsmStorage.o ../../vhsm/MessageHandler.o ../../protocol/vhsm_transport.pb.o ../../netlink_transport/VhsmMessageTransport.o vhsm.o MessageHandlerTest.o mh_tests.o

VHSM_OBJECTS = VhsmStorage.o ../../vhsm/MessageHandler.o ../../protocol/vhsm_transport.pb.o ../../netlink_transport/VhsmMessageTransport.o ../../vhsm/vhsm.o VhsmTest.o vhsm_tests.o

all: mh_tests vhsm_tests

mh_tests: vhsm.o mh_tests.o MessageHandlerTest.o
	$(CC) $(MH_OBJECTS) -o mh_tests $(LIBS)

vhsm.o: vhsm_mock.cpp
	$(CC) -c vhsm_mock.cpp -o vhsm.o

mh_tests.o: mh_tests.cpp
	$(CC) -c mh_tests.cpp

MessageHandlerTest.o: 
	$(CC) -c MessageHandlerTest.cpp



vhsm_tests: VhsmStorage.o VhsmTest.o vhsm_tests.o
	$(CC) $(VHSM_OBJECTS) -o vhsm_tests $(LIBS)	

VhsmTest.o: VhsmTest.cpp
	$(CC) -c VhsmTest.cpp

VhsmStorage.o: vhsm_storage_mock.cpp
	$(CC) -c vhsm_storage_mock.cpp -o VhsmStorage.o

vhsm_tests.o: vhsm_tests.cpp ../../vhsm/vhsm.cpp
	$(CC) -c vhsm_tests.cpp


clean:
	rm -f *.o *~ *.out vhsm mh_tests vhsm_tests
