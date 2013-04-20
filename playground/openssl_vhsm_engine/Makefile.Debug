all: test_engine

test_engine: main.c
	gcc -std=c99 -ggdb3 -c -I.. -fPIC main.c
	gcc -ggdb3 -shared -fPIC -o test_engine.so main.o -L/home/user/openssl_build_2/lib -lcrypto -lssl -ldl
clean:
	rm -f *.o *.so
