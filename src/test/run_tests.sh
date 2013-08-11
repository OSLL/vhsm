if [ ! -f  ./test_login -o ! -f ./test_key_mgmt -o ! -f ./test_hmac -o ! -f ./test_digest ]; then
	echo "Tests not found. Please run make from tests directory."
	exit
fi

echo "=== TEST LOGIN ==="
./test_login
echo "=== TEST KEY MANAGEMENT ==="
./test_key_mgmt
echo "=== TEST DIGEST ==="
./test_digest
echo "=== TEST HMAC ==="
./test_hmac
echo "=== TEST PARALLEL ==="
./test_parallel

