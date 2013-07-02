CC = g++ -I../files_transport -I../protocol -I./esapi -I../netlink_transport
LIBS = -lpthread -lprotobuf -lcryptopp -lsqlite3

OBJECTS = EncryptedStorageFactory.o MessageHandler.o VhsmStorage.o ../protocol/vhsm_transport.pb.o ./esapi_file_impl/esapi.a ../netlink_transport/VhsmMessageTransport.o vhsm.o

all: vhsm vhsm_admin storage

vhsm: esapi_impl esfactory vhsm_storage vhsm.o msg_handler
	$(CC) $(OBJECTS) -o vhsm $(LIBS)

vhsm_admin:
	$(CC) vhsm_admin.cpp EncryptedStorageFactory.o ./esapi_file_impl/esapi.a -o vhsm_admin $(LIBS)

vhsm.o:
	$(CC) -c vhsm.cpp -o vhsm.o

esapi_impl:
	$(MAKE) -C esapi_file_impl

esfactory: EncryptedStorageFactory.cpp
	$(CC) -c EncryptedStorageFactory.cpp -o EncryptedStorageFactory.o $(LIBS)

vhsm_storage: VhsmStorage.cpp
	$(CC) -Wno-unused-variable -c VhsmStorage.cpp -o VhsmStorage.o $(LIBS)

msg_handler: MessageHandler.cpp
	$(CC) -Wno-unused-variable -c MessageHandler.cpp -o MessageHandler.o $(LIBS)

storage: storage.cpp
	$(CC) storage.cpp VhsmStorage.o -o storage $(LIBS)

clean:
	$(MAKE) -C esapi clean
	$(MAKE) -C esapi_file_impl clean
	rm -f *.o *~ *.out vhsm vhsm_admin storage
