#TODO uncomment when openssl_engine is fixed.
#all: test_application openssl_engine
all: test_application

test_application: vhsm_api
	$(MAKE) -C test_app

vhsm_api:
	$(MAKE) -C vhsm_api_prototype_impl

openssl_engine:
	$(MAKE) -C openssl_vhsm_engine

clean:
	$(MAKE) -C vhsm_api_prototype_impl clean
	$(MAKE) -C openssl_vhsm_engine clean
	$(MAKE) -C test_app clean
	rm *~ -f
