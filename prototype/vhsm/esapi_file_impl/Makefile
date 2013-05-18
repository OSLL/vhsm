CC = g++ -I../esapi
LIBS = -lcryptopp
AR = ar crf

OBJECTS = EncryptedStorage.o

all: storage
	$(AR) esapi.a $(OBJECTS)

storage: EncryptedStorage.cpp
	$(CC) -c EncryptedStorage.cpp -o EncryptedStorage.o $(LIBS)

clean:
	rm *~ *.o *.out *.a -f
