all: build_transport build_client build_vhsm build_tests

build_transport:
	$(MAKE) -C netlink_transport

build_client: build_protocol
	$(MAKE) -C client

build_vhsm: build_protocol
	$(MAKE) -C vhsm

build_protocol:
	$(MAKE) -C protocol

build_tests:
	$(MAKE) -C test

deb: build_transport build_client build_protocol
	rm -rf tmp
	mkdir tmp
	mkdir -p tmp/usr/bin
	cp vhsm/vhsm tmp/usr/bin/
	cp vhsm/vhsm_admin tmp/usr/bin/
	mkdir -p tmp/usr/include/vhsm/
	cp client/vhsm_api_prototype/*.h tmp/usr/include/vhsm/
	mkdir -p tmp/usr/lib/
	cp client/vhsm_api_prototype_impl/vhsm_api.a tmp/usr/lib/
	mkdir -p tmp/lib/modules/2.6.32-5-openvz-amd64/kernel/crypto/
	cp netlink_transport/kernel/vhsm_transport.ko tmp/lib/modules/2.6.32-5-openvz-amd64/kernel/crypto/
	cp -r DEBIAN tmp
	md5deep -r tmp/usr tmp/lib tmp/etc > tmp/DEBIAN/md5sums
	fakeroot dpkg-deb --build tmp
	mv tmp.deb vhsm_0.1_amd64.deb
	rm -rf tmp

clean:
	$(MAKE) -C client clean
	$(MAKE) -C protocol clean
	$(MAKE) -C vhsm clean
	$(MAKE) -C netlink_transport clean
	$(MAKE) -C test clean
	rm *~ -f
