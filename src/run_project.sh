#!/bin/bash

TESTS=$PWD"/test"
VHSM_CNT_DIR="/var/lib/vz/private/411"
VHSM_CNT=411


if [[ `vzlist | grep $VHSM_CNT` ]]; then
  vzctl stop $VHSM_CNT
  vzctl delete $VHSM_CNT
fi

echo -e "CREATING CONTAINER"

vzctl create $VHSM_CNT --ostemplate debian-6.0-x86_64
vzctl set $VHSM_CNT --ipadd 192.168.5.1 --save
vzctl start $VHSM_CNT

cp /usr/lib/libprotobuf* /var/lib/vz/private/411/usr/lib/
cp /usr/lib/libcrypto* /var/lib/vz/private/411/usr/lib/

echo -e "INIT NETLINK MODULE"
insmod ./netlink_transport/kernel/vhsm_transport.ko vhsm_veid=$VHSM_CNT

echo -e "INITILIZING ENCRYPTED STORAGE\n"

cp "vhsm/vhsm" $VHSM_CNT_DIR
rm -rf $VHSM_CNT_DIR"/data"
./vhsm/vhsm_admin i $VHSM_CNT_DIR"/data"
./vhsm/vhsm_admin c $VHSM_CNT_DIR"/data" user password

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
