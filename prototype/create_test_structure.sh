#!/bin/bash

TEST_DIR="test_drive"
CLIENT_DIR=$TEST_DIR"/1"

IO_VHSM_TO_HOST=$TEST_DIR"/io_vhsm_to_host"
IO_VHSM_FROM_HOST=$TEST_DIR"/io_vhsm_from_host"

IO_CLIENT_TO_HOST=$CLIENT_DIR"/send_data"
IO_CLIENT_FROM_HOST=$CLIENT_DIR"/recv_data"



echo -e "RUNNING MAKE CLEAN\n"

make clean

echo -e "RUNNING MAKE\n"

make



if [[ -e $TEST_DIR ]]; then
  echo -e "$TEST_DIR/ ALREADY EXISTS. REMOVING.\n"
  rm -rf $TEST_DIR
fi;

echo -e "CREATING FILES AND DIRECTORIES\n"

mkdir $TEST_DIR
mkdir $CLIENT_DIR

touch $IO_VHSM_FROM_HOST
touch $IO_VHSM_TO_HOST
touch $IO_CLIENT_FROM_HOST
touch $IO_CLIENT_TO_HOST

echo -e "COPYING BINARIES\n"

cp "client/test_app/test_app" $CLIENT_DIR
cp "vhsm/vhsm" $TEST_DIR
cp "host/host" $TEST_DIR
cp "vhsm/vhsm_admin" $TEST_DIR
cp "client/openssl_vhsm_engine/test_engine.so" $CLIENT_DIR
cp "client/openssl_vhsm_engine/e_test_app" $CLIENT_DIR


echo -e "INITILIZING ENCRYPTED STORAGE\n"

cd $TEST_DIR
./vhsm_admin i ./data
./vhsm_admin c ./data user password
