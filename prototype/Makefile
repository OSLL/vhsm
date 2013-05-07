build_client: build_protocol
	$(MAKE) -C client

build_vhsm: build_protocol
	$(MAKE) -C vhsm

build_protocol:
	$(MAKE) -C protocol

clean:
	$(MAKE) -C client clean
	$(MAKE) -C protocol clean
	$(MAKE) -C vhsm clean
	rm *~ -f
