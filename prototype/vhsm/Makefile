CC = g++ -I../files_transport -I../protocol
LIBS = -lprotobuf -lcryptopp

all: vhsm

vhsm: msg_handler
	$(CC) vhsm.cpp MessageHandler.o ../protocol/vhsm_transport.pb.o -o vhsm $(LIBS)

msg_handler: MessageHandler.cpp
	$(CC) -c MessageHandler.cpp -o MessageHandler.o $(LIBS)

clean:
	$(MAKE) -C esapi clean
	$(MAKE) -C esapi_file_impl clean
	rm -f *.o *~ *.out vhsm
