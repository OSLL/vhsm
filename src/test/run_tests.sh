if [ ! -f  ./test_digest -o ! -f ./test_create_key -o ! -f ./test_hmac -o ! -f ./test_gen_keys -o ! -f ./test_enum_keys ]; then
	echo "Tests not found. Please run make from tests directory."
	exit
fi

echo "=== TEST DIGEST ==="
./test_digest
echo "=== TEST CREATE KEY ==="
./test_create_key
echo "=== TEST HMAC ==="
./test_hmac
echo "=== TEST GEN KEYS ==="
./test_gen_keys
echo "=== TEST ENUM KEYS ==="
./test_enum_keys

