all: build_transport build_client build_vhsm build_host

build_transport:
	$(MAKE) -C netlink_transport

build_client: build_protocol
	$(MAKE) -C client

build_vhsm: build_protocol
	$(MAKE) -C vhsm

build_protocol:
	$(MAKE) -C protocol

build_host:
	$(MAKE) -C host

clean:
	$(MAKE) -C client clean
	$(MAKE) -C protocol clean
	$(MAKE) -C vhsm clean
	$(MAKE) -C files_transport clean
	$(MAKE) -C netlink_transport clean
	$(MAKE) -C host clean
	rm *~ -f
