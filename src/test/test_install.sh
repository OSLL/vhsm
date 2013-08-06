#!/bin/bash

mkdir ../../build
cd ../../build

abort() {
    echo 1>&2 "$1"
    exit 1
}

if [ `id -u` -ne 0 ]; then
	abort "This program must be run with administrator privileges."
fi

TESTS=$PWD"/test"
VHSM_CNT=412
VHSM_CNT_DIR="/var/lib/vz/private/"$VHSM_CNT
CLIENT_CNT=413
CLIENT_CNT_DIR="/var/lib/vz/private/"$CLIENT_CNT

cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ../src
make
make install

if [ ! -e /lib/modules/2.6.32-5-openvz-amd64/kernel/crypto/vhsm_transport.ko ]; then 
  abort "ERROR: vhsm_transport.ko not found."
fi
if [ ! -e /usr/bin/vhsm ]; then 
  abort "ERROR: vhsm not found."
fi
if [ ! -e /usr/bin/vhsm_admin ]; then
        abort "ERROR: vhsm_admin not found."
fi
if [ ! -e /usr/include/vhsm_api ]; then
        abort "ERROR: /usr/include/vhsm_api not found."
fi
if [ ! -e /usr/lib/libvhsmapi.a ]; then
        abort "ERROR: /usr/lib/libvhsmapi.a not found."
fi

depmod
modprobe vhsm_transport vhsm_veid=$VHSM_CNT

echo "===CREATE VHSM CONTAINER==="

if [[ ! `vzlist | grep $VHSM_CNT` ]]; then
  vzctl create $VHSM_CNT --ostemplate debian-6.0-x86_64
  vzctl start $VHSM_CNT
fi

CONTAINER_LIB=/var/lib/vz/private/"$VHSM_CNT"/usr/lib/

if [ ! -d "$CONTAINER_LIB" ]; then
	abort "Could not find $CONTAINER_LIB directory. Try to recreate conatainer with id $VHSM_CNT."
fi

cp /usr/lib/libprotobuf* "$CONTAINER_LIB"
cp /usr/lib/libcrypto* "$CONTAINER_LIB"
cp "/usr/bin/vhsm" $VHSM_CNT_DIR
/usr/bin/vhsm_admin i $VHSM_CNT_DIR"/data"
vzctl exec $VHSM_CNT /vhsm &


echo "===CREATE CLIENT CONTAINER AND COPY TESTS==="

if [[ `vzlist | grep $CLIENT_CNT` ]]; then
  vzctl stop $CLIENT_CNT
  vzctl delete $CLIENT_CNT
fi

vzctl create $CLIENT_CNT --ostemplate debian-6.0-x86_64
vzctl start $CLIENT_CNT

cp -r /usr/include/vhsm_api $CLIENT_CNT_DIR"/usr/include/"
cp  "/usr/lib/libvhsmapi.a" $CLIENT_CNT_DIR"/usr/lib/libvhsmapi.a"
cp -r /usr/bin/tests $CLIENT_CNT_DIR"/usr/bin/"
cp /usr/bin/vhsm_user_admin $CLIENT_CNT_DIR"/usr/bin/vhsm_user_admin"
