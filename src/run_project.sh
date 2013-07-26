#!/bin/bash

if [ `id -u` -ne 0 ]; then
	abort "This program must be run with administrator privileges."
fi

TESTS=$PWD"/test"
VHSM_CNT_DIR="/var/lib/vz/private/411"
VHSM_CNT=411

not_exists() {
    which "$1" &>/dev/null
    return $([ $? -ne 0 ])
}

if not_exists vzlist ; then
	echo "vzlist not found. Please try to install vzctl"
	exit 1
fi

if not_exists vzctl ; then
	echo "vzctl not found. Please try to install vzctl"
	exit 1
fi

if [[ `vzlist | grep $VHSM_CNT` ]]; then
  vzctl stop $VHSM_CNT
  vzctl delete $VHSM_CNT
fi

echo -e "CREATING CONTAINER"

vzctl create $VHSM_CNT --ostemplate debian-6.0-x86_64
vzctl set $VHSM_CNT --ipadd 192.168.5.1 --save
vzctl start $VHSM_CNT

CONTAINER_LIB=/var/lib/vz/private/411/usr/lib

if [ ! -d "$CONTAINER_LIB" ]; then
	echo "Could not find $CONTAINER_LIB directory. Try to recreate conatainer with id $VHSM_CNT."
	exit 1
fi

cp /usr/lib/libprotobuf* "$CONTAINER_LIB"
cp /usr/lib/libcrypto* "$CONTAINER_LIB"

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
