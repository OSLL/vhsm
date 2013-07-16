#!/bin/bash

TEST_DIR="test_drive"

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
#mkdir $CLIENT_DIR

echo -e "COPYING BINARIES\n"

#cp "client/test_app/test_app" $CLIENT_DIR
cp "vhsm/vhsm" $TEST_DIR
cp "vhsm/vhsm_admin" $TEST_DIR
#cp "client/openssl_vhsm_engine/test_engine.so" $CLIENT_DIR
#cp "client/openssl_vhsm_engine/e_test_app" $CLIENT_DIR

echo -e "MAKE NETLINK MODULE"
cd ./netlink_transport/kernel/
make
