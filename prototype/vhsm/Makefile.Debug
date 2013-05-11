CC = g++ -c -I../protocol -lprotobuf -lcryptopp

all: msg_handler

msg_handler: MessageHandler.cpp
	$(CC) MessageHandler.cpp

clean:
	rm -f *.o *~ *.out
