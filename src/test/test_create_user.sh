#!/bin/bash
VHSM_CNT=412
VHSM_CNT_DIR="/var/lib/vz/private/"$VHSM_CNT"/data"
if [ ! -e $VHSM_CNT_DIR ]; then
  echo "ERROR: path to base not found."
  exit 1
fi

echo "=== CREATE NEW USER ==="
vhsm_admin c $VHSM_CNT_DIR user password
echo $?
if (( $? == 0 )); then
  echo "OK"
else
  echo "Error while creating new user"
fi
echo "=== CREATE USER OF THE SAME NAME ==="
vhsm_admin c $VHSM_CNT_DIR user pass
if (( $? == 1 )); then
  echo "OK"
else
  echo "Error while creating user of the same name"
fi
echo "=== CREATE SECOND NEW USER ==="
vhsm_admin c $VHSM_CNT_DIR user2 password2
if (( $? == 0 )); then
  echo "OK"
else
  echo "Error while creating second user"
fi

