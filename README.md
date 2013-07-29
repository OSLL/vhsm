vhsm
====

Virtual HSM

VHSM is a software package for storing secret data and computing cryptographic functions, outside virtual scope of an application.

Project's issue tracker and wiki: http://osll.spb.ru/projects/vhsm

Full documentation you can find at [doc](/src/doc).

#Installation

## Prerequisites

To build the source the following must first be installed on your system:
* g++
*	linux-headers-2.6.32-5-openvz
*	protobuf-compiler, libprotobuf7, libprotoc7, libprotobuf-dev;
*	libcrypto++-dev;
*	libssl-dev;
*	libsqlite3-dev

## OpenSSL configuration

The next lines should be appended at /etc/ssl/openssl.cnf

At the beginning:
```
openssl_conf = openssl_def
```

At the end:
```
[openssl_def]
engines = engine_section
[engine_section]
test_engine = test_engine_section

[test_engine_section]
engine_id = test_engine
dynamic_path = /path/to/test_engine.so # %repository_root%/test_drive/1/test_engine.so
# here should be actual username and pass for registration in VHSM
username = user
password = password
init = 0
```

## Building
Run `make` from [src/netlink_transport/kernel](/src/netlink_transport/kernel) and then from [src](/src).

# Testing
After building VHSM is a good idea to test it, using
```
./run_project.sh
```

# Copyright and license
