CC = g++ -I../esapi
LIBS = -lcryptopp
AR = ar crf

OBJECTS = FSEncryptedStorage.o ESCypher.o

all: storage cypher
	$(AR) esapi.a $(OBJECTS)

storage: cypher FSEncryptedStorage.cpp
	$(CC) -c FSEncryptedStorage.cpp -o FSEncryptedStorage.o $(LIBS)

cypher: ESCypher.cpp
	$(CC) -c ESCypher.cpp -o ESCypher.o $(LIBS)

clean:
	rm *~ *.o *.out *.a -f
