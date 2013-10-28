VHSM
====

Virtual HSM

VHSM is a software package for storing secret data and computing cryptographic functions outside virtual scope of an application.

Project issue tracker and wiki: http://dev.osll.ru/projects/vhsm

## Requirements

**Warning**: this project requires OpenVZ environment. Install the following packages to build the project on your system. On CentOS use [EPEL repositories](http://fedoraproject.org/wiki/EPEL/FAQ#How_can_I_install_the_packages_from_the_EPEL_software_repository.3F) and this [OpenVZ guide](http://www.howtoforge.com/installing-and-using-openvz-on-centos-6.4).

| package                  | deb                           | rpm               |
| ------------------------ | ----------------------------- | ----------------- |
| CMake **2.8**            | cmake                         | cmake28           |
| OpenVZ kernel headers    | linux-headers-2.6.32-5-openvz | vzkernel-headers  |
| Google protobuf compiler | protobuf-compiler             | protobuf-compiler |
| libprotobuf		   | libprotobuf-dev               | protobuf-devel    |
| crypto++ 5.6.2           | libcrypto++-dev               | cryptopp-devel    |
| SQLite 3 		   | libsqlite3-dev                | sqlite-devel      |
| *(optional)* cppunit	   | libcppunit-dev                | cppunit-devel     |

## Building
Just run `cmake` and then `make`. CMake custom options:

* BUILD_vhsm_user_api - build vhsm user API library (ON);
* BUILD_transport_module - build vhsm transport kernel module (ON);
* BUILD_vhsm - build vhsm server (ON);
* BUILD_pam - build PAM module (ON);
* BUILD_tests - build vhsm tests (OFF);

You may build binary packages with the command `make pkg`.

## Installation
*installation and configuration system coming soon*

## Usage
*vhsm user tool description coming soon* 

