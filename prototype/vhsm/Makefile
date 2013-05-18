CC = g++ -I../files_transport -I../protocol
LIBS = -lprotobuf -lcryptopp

OBJECTS = MessageHandler.o ../protocol/vhsm_transport.pb.o esapi_file_impl/esapi.a

all: vhsm

vhsm: msg_handler esapi_impl
	$(CC) vhsm.cpp $(OBJECTS) -o vhsm $(LIBS)

msg_handler: MessageHandler.cpp
	$(CC) -c MessageHandler.cpp -o MessageHandler.o $(LIBS)

esapi_impl:
	$(MAKE) -C esapi_file_impl

clean:
	$(MAKE) -C esapi clean
	$(MAKE) -C esapi_file_impl clean
	rm -f *.o *~ *.out vhsm
