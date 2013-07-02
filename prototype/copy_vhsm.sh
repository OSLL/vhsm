cp test_drive/vhsm /var/lib/vz/private/411/
#cp -r test_drive/data /var/lib/vz/private/411/ 
#cp -r ../playground/storage_prototype/data /var/lib/vz/private/411/
rm -rf /var/lib/vz/private/411/data
mkdir /var/lib/vz/private/411/data
cp vhsm/storage /var/lib/vz/private/411/
cd /var/lib/vz/private/411/
./storage
