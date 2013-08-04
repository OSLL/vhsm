if [ ! -f  ./test_login -o ! -f ./test_key_mgmt -o ! -f ./test_hmac ]; then
	echo "Tests not found. Please run make from tests directory."
	exit
fi

echo "=== TEST LOGIN ==="
./test_login
echo "=== TEST KEY MANAGEMENT ==="
./test_key_mgmt
echo "=== TEST HMAC ==="
./test_hmac

