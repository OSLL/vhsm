all: cryptopp_test keyczar_test

cryptopp_test: cryptopp_test.cpp
	g++ -o cryptopp_test cryptopp_test.cpp -lcryptopp -lcrypto

keyczar_test: keyczar_test.cpp
	g++ -o keyczar_test keyczar_test.cpp -Wl,-rpath=/home/user/keyczar_build/lib -I/home/user/keyczar_build/include -L/home/user/keyczar_build/lib -lkeyczar 

clean:
	rm -f *.o cryptopp_test keyczar_test
