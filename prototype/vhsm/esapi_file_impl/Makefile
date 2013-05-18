CC = g++ -I../esapi
LIBS = -lcryptopp
AR = ar crf

OBJECTS = EncryptedStorage.o ESCypher.o

all: storage cypher
	$(AR) esapi.a $(OBJECTS)

storage: cypher EncryptedStorage.cpp
	$(CC) -c EncryptedStorage.cpp -o EncryptedStorage.o $(LIBS)

cypher: ESCypher.cpp
	$(CC) -c ESCypher.cpp -o ESCypher.o $(LIBS)

clean:
	rm *~ *.o *.out *.a -f
