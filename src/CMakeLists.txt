cmake_minimum_required(VERSION 2.8)

project(vhsm)

option(BUILD_vhsm_user_api "build vhsm user API library" ON)
option(BUILD_transport_module "build vhsm transport kernel module" ON)
option(BUILD_vhsm "build vhsm daemon" ON)
option(BUILD_tests "build tests" ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

if(NOT (${CMAKE_SYSTEM_VERSION} MATCHES "openvz"))
	message(SEND_WARNING "This project reqiures OpenVZ environment")
endif()

# ------------------------------------------------------------------------

find_package(Protobuf REQUIRED)
if(NOT PROTOBUF_FOUND)
	message(SEND_ERROR "Protobuf library and compiler are required")
	return()	
endif()

set(LINUX_HEADERS_PATH /lib/modules/${CMAKE_SYSTEM_VERSION}/build)

if(BUILD_transport_module)
	if(NOT EXISTS ${LINUX_HEADERS_PATH})
		message(SEND_ERROR "Transport module requires linux-headers package")
	endif()
endif()

if(BUILD_vhsm)
	find_package(Crypto++ REQUIRED)
	if(NOT CRYPTO++_FOUND)
		message(SEND_ERROR "Crypto++ is required for building VHSM")
	else()
		include_directories(${CRYPTO++_INCLUDE_DIR})
	endif()	

	find_package(SQLite3 REQUIRED)
	if(NOT SQLITE3_FOUND)
		message(SEND_ERROR "SQLite3 is required for building VHSM")
	else()
		include_directories(${SQLITE3_INCLUDE_DIRS})
	endif()
endif()

if(BUILD_tests)
	find_package(CppUnit REQUIRED)
	if(NOT CPPUNIT_FOUND)
		message(SEND_ERROR "cppunit is required for building tests")	
	else()
		include_directories(${CPPUNIT_INCLUDE_DIR})
	endif()
endif()

SET(CMAKE_THREAD_PREFER_PTHREAD, TRUE)
find_package(Threads REQUIRED)

# ------------------------------------------------------------------------

add_subdirectory(protocol)
add_subdirectory(netlink_transport)

if(BUILD_vhsm_user_api)
	add_subdirectory(client)
	add_dependencies(vhsmapi vhsm_transport_messages)
	if(BUILD_tests)
		add_dependencies(test_app vhsmapi vhsm_transport.pb)
	endif(BUILD_tests)
endif(BUILD_vhsm_user_api)

if(BUILD_transport_module)
	add_custom_target(transport_module
		COMMAND make
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/netlink_transport/kernel
	)
	add_dependencies(VhsmMessageTransport transport_module)
	install(FILES ${CMAKE_SOURCE_DIR}/netlink_transport/kernel/vhsm_transport.ko DESTINATION ../lib/modules/2.6.32-5-openvz-amd64/kernel/crypto/)
endif(BUILD_transport_module)

if(BUILD_vhsm)
	add_subdirectory(vhsm)
	add_dependencies(vhsm vhsm_transport_messages vhsm_transport.pb)
endif(BUILD_vhsm)

if(BUILD_tests)
	add_subdirectory(test)
endif(BUILD_tests)

# ------------------------------------------------------------------------
SET (CPACK_GENERATOR "DEB")

SET (CPACK_DEBIAN_PACKAGE_VERSION "0.1")
SET (CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
SET (CPACK_DEBIAN_PACKAGE_SECTION "utils")
SET (CPACK_DEBIAN_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
SET (CPACK_DEBIAN_PACKAGE_DEPENDS "libcrypto++8, libprotobuf6, vzctl")
SET (CPACK_PACKAGE_DESCRIPTION_SUMMARY "virtual HSM\n Virtual HSM is software package desigend to store secret data and compute cryptographic functions using the secrets out of virtual environment.")
SET (CPACK_PACKAGE_CONTACT "virtual-hsm team <virtual-hsm@lists.osll.spb.ru>")
SET (CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${CPACK_DEBIAN_PACKAGE_VERSION}_${CPACK_DEBIAN_ARCHITECTURE}")
SET (CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_SOURCE_DIR}/DEBIAN/postinst" "${CMAKE_SOURCE_DIR}/DEBIAN/prerm")

INCLUDE (CPack)
