all: test_engine test_app

test_engine: main.c
	gcc -fPIC -c main.c
	gcc -fPIC -shared -o test_engine.so main.o -lcrypto -lssl -ldl

test_app: test.c
	gcc -o test_app test.c -lcrypto -lssl -ldl

clean:
	rm -f *.o *.so test_app
