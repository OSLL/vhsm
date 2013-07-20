CC = g++ -I../protocol -I../netlink_transport
LIBS = -lpthread -lprotobuf -lcryptopp -lsqlite3

OBJECTS = VhsmStorage.o MessageHandler.o ../protocol/vhsm_transport.pb.o ../netlink_transport/VhsmMessageTransport.o vhsm.o

all: vhsm vhsm_admin

vhsm: vhsm_storage msg_handler vhsm.o
	$(CC) $(OBJECTS) -o vhsm $(LIBS)

vhsm_admin: vhsm_admin.cpp vhsm_storage
	$(CC) vhsm_admin.cpp VhsmStorage.o -o vhsm_admin $(LIBS)

vhsm.o: vhsm.cpp
	$(CC) -c vhsm.cpp -o vhsm.o

vhsm_storage: VhsmStorage.cpp
	$(CC) -Wno-unused-variable -c VhsmStorage.cpp -o VhsmStorage.o $(LIBS)

msg_handler: MessageHandler.cpp
	$(CC) -Wno-unused-variable -c MessageHandler.cpp -o MessageHandler.o $(LIBS)

clean:
	rm -f *.o *~ *.out vhsm vhsm_admin
