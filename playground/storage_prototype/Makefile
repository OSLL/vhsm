all: storage

storage: main.cpp
	g++ main.cpp -o storage -lsqlite3 -lcryptopp
	mkdir data

clean:
	rm -f storage -r ./data/
