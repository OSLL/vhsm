CC = g++ -I../esapi
LIBS = -lcryptopp
AR = ar crf

OBJECTS = FSESNamespace.o ESCypher.o FSEncryptedStorage.o

all: storage cypher namespace
	$(AR) esapi.a $(OBJECTS)

namespace: FSESNamespace.cpp
	$(CC) -c FSESNamespace.cpp -o FSESNamespace.o $(LIBS)

storage: cypher FSEncryptedStorage.cpp
	$(CC) -c FSEncryptedStorage.cpp -o FSEncryptedStorage.o $(LIBS)

cypher: ESCypher.cpp
	$(CC) -c ESCypher.cpp -o ESCypher.o $(LIBS)

clean:
	rm *~ *.o *.out *.a -f
