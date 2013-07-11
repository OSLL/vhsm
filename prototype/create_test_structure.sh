#!/bin/bash

TEST_DIR="test_drive"
CLIENT_DIR=$TEST_DIR"/1"
TESTS=$PWD"/client/test_app"

echo -e "RUNNING MAKE CLEAN\n"

make clean

echo -e "RUNNING MAKE\n"

make
cd ./netlink_transport/kernel/
make
cd ../../


if [[ -e $TEST_DIR ]]; then
  echo -e "$TEST_DIR/ ALREADY EXISTS. REMOVING.\n"
  rm -rf $TEST_DIR
fi;

echo -e "CREATING FILES AND DIRECTORIES\n"

mkdir $TEST_DIR
mkdir $CLIENT_DIR


echo -e "COPYING BINARIES\n"

#cp "client/test_app/test_app" $CLIENT_DIR
cp "vhsm/vhsm" $TEST_DIR
#cp "host/host" $TEST_DIR
cp "vhsm/vhsm_admin" $TEST_DIR
cp "client/openssl_vhsm_engine/test_engine.so" $CLIENT_DIR
cp "client/openssl_vhsm_engine/e_test_app" $CLIENT_DIR

echo -e "INIT NETLINK MODULE"
insmod ./netlink_transport/kernel/vhsm_transport.ko

echo -e "COPY VHSM"
./copy_vhsm.sh

echo -e "INITILIZING ENCRYPTED STORAGE\n"

cd /var/lib/vz/private/411/ 
./vhsm &

echo -e "PAUSE"
sleep 5
echo -e "RUN TESTS"
cd $TESTS
./run_tests.sh
