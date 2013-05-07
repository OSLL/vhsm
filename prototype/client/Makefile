all: vhsm_api openssl_engine

vhsm_api:
	$(MAKE) -C vhsm_api_prototype_impl

openssl_engine:
	$(MAKE) -C openssl_vhsm_engine

clean:
	$(MAKE) -C vhsm_api_prototype_impl clean
	$(MAKE) -C openssl_vhsm_engine clean
	rm *~ -f
