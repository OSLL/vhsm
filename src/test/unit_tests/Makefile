CC = g++ -I../../vhsm -I../../protocol -I../../netlink_transport
LIBS = -lpthread -lprotobuf -lcryptopp -lsqlite3 -lcppunit

OBJECTS = ../../vhsm/VhsmStorage.o ../../protocol/vhsm_transport.pb.o ../../netlink_transport/VhsmMessageTransport.o vhsm.o MessageHandlerTest.o main.o

all: mh_tests

mh_tests: vhsm.o main.o MessageHandlerTest.o
	$(CC) $(OBJECTS) -o mh_tests $(LIBS)

main.o: main.cpp
	$(CC) -c main.cpp

MessageHandlerTest.o: 
	$(CC) -c MessageHandlerTest.cpp

vhsm.o: vhsm_mock.cpp
	$(CC) -c vhsm_mock.cpp -o vhsm.o

clean:
	rm -f *.o *~ *.out vhsm mh_tests
