#!/bin/bash

TEST_DIR="test_drive"
CLIENT_DIR=$TEST_DIR"/tests"
TESTS=$PWD"/test"
VHSM_CNT_DIR="/var/lib/vz/private/411"
VHSM_CNT=411

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
#mkdir $CLIENT_DIR

echo -e "COPYING BINARIES\n"

#cp "client/test_app/test_app" $CLIENT_DIR
cp "vhsm/vhsm" $TEST_DIR
cp "vhsm/vhsm_admin" $TEST_DIR
#cp "client/openssl_vhsm_engine/test_engine.so" $CLIENT_DIR
#cp "client/openssl_vhsm_engine/e_test_app" $CLIENT_DIR

echo -e "INITILIZING ENCRYPTED STORAGE\n"

cp "vhsm/vhsm" $VHSM_CNT_DIR
rm -rf $VHSM_CNT_DIR"/data"
./vhsm/vhsm_admin i $VHSM_CNT_DIR"/data"
./vhsm/vhsm_admin c $VHSM_CNT_DIR"/data" user password

echo -e "INIT NETLINK MODULE"
insmod ./netlink_transport/kernel/vhsm_transport.ko vhsm_veid=$VHSM_CNT

echo -e "STARTING VHSM"

#cd $VHSM_CNT_DIR 
#./vhsm &
vzctl exec $VHSM_CNT ./vhsm &

echo -e "PAUSE"
sleep 5
echo -e "RUN TESTS"
cd $TESTS
./run_tests.sh

echo -e "STOPPING VHSM"

killall vhsm
rmmod vhsm_transport
