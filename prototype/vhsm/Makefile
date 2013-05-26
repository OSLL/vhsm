CC = g++ -I../files_transport -I../protocol -I./esapi
LIBS = -lpthread -lprotobuf -lcryptopp

OBJECTS = EncryptedStorageFactory.o MessageHandler.o ../protocol/vhsm_transport.pb.o ./esapi_file_impl/esapi.a

all: vhsm vhsm_admin

vhsm: msg_handler esapi_impl esfactory
	$(CC) vhsm.cpp $(OBJECTS) -o vhsm $(LIBS)

vhsm_admin:
	$(CC) vhsm_admin.cpp $(OBJECTS) -o vhsm_admin $(LIBS)

msg_handler: MessageHandler.cpp
	$(CC) -c MessageHandler.cpp -o MessageHandler.o $(LIBS)

esfactory: EncryptedStorageFactory.cpp
	$(CC) -c EncryptedStorageFactory.cpp -o EncryptedStorageFactory.o $(LIBS)

esapi_impl:
	$(MAKE) -C esapi_file_impl

clean:
	$(MAKE) -C esapi clean
	$(MAKE) -C esapi_file_impl clean
	rm -f *.o *~ *.out vhsm vhsm_admin
