cp test_drive/vhsm /var/lib/vz/private/411/
#cp -r test_drive/data /var/lib/vz/private/411/ 
rm -rf /var/lib/vz/private/411/data
./vhsm/vhsm_admin i /var/lib/vz/private/411/data
./vhsm/vhsm_admin c /var/lib/vz/private/411/data user password
