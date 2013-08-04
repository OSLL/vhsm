#!/bin/bash

if [ `id -u` -ne 0 ]; then
  echo "This program must be run with administrator privileges."
  exit 1
fi

VHSM_CNT=412
CLIENT_CNT=413

if [ -e /lib/modules/2.6.32-5-openvz-amd64/kernel/crypto/vhsm_transport.ko ]; then 
  rm /lib/modules/2.6.32-5-openvz-amd64/kernel/crypto/vhsm_transport.ko
fi

if [ -e /usr/bin/vhsm ]; then 
  rm /usr/bin/vhsm
fi

if [ -e /usr/bin/vhsm_admin ]; then
  rm /usr/bin/vhsm_admin
fi

if [ -e /usr/bin/vhsm_user_admin ]; then
  rm /usr/bin/vhsm_user_admin
fi

if [ -e /usr/include/vhsm_api ]; then
  rm -rf /usr/include/vhsm_api
fi

if [ -e /usr/lib/libvhsmapi.a ]; then
  rm /usr/lib/libvhsmapi.a
fi

if [ -e /usr/bin/tests ]; then
  rm -rf /usr/bin/tests
fi

if [[ `vzlist | grep -o $CLIENT_CNT` ]]; then
  vzctl stop $CLIENT_CNT
  vzctl delete $CLIENT_CNT
fi

if [[ `vzlist | grep -o $VHSM_CNT` ]]; then
  vzctl stop $VHSM_CNT
  vzctl delete $VHSM_CNT
fi
