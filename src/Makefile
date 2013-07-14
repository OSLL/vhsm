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

clean:
	$(MAKE) -C client clean
	$(MAKE) -C protocol clean
	$(MAKE) -C vhsm clean
	$(MAKE) -C netlink_transport clean
	$(MAKE) -C test clean
	rm *~ -f
