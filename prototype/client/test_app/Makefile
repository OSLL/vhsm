CC = g++ -I../vhsm_api_prototype

test_app:
	$(CC) test_app.cpp ../vhsm_api_prototype_impl/vhsm_api.a -o test_app -lprotobuf -lpthread

clean:
	rm *~ *.out *.o test_app -f
