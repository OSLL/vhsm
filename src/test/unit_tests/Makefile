CC = g++ -I../../vhsm -I../../protocol -I../../netlink_transport
LIBS = -lpthread -lprotobuf -lcryptopp -lsqlite3

OBJECTS = ../../vhsm/MessageHandler.o ../../vhsm/VhsmStorage.o ../../protocol/vhsm_transport.pb.o ../../netlink_transport/VhsmMessageTransport.o vhsm.o

all: vhsm

vhsm: vhsm.o
	$(CC) $(OBJECTS) -o vhsm $(LIBS)


vhsm.o: vhsm_mock.cpp
	$(CC) -c vhsm_mock.cpp -o vhsm.o

clean:
	rm -f *.o *~ *.out vhsm vhsm_admin
