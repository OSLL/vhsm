cmake_minimum_required(VERSION 2.8)

project(vhsm)

include_directories(..)
include_directories(${PAM_INCLUDE_DIR})

add_library(pam-vhsm SHARED pam-vhsm.cpp)

target_link_libraries(pam-vhsm vhsmapi ${PROTOBUF_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	install(TARGETS pam-vhsm DESTINATION /lib/security/)
else()
	install(TARGETS pam-vhsm DESTINATION lib)
endif(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
