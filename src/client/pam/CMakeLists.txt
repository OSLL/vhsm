cmake_minimum_required(VERSION 2.8)

project(vhsm)

include_directories(..)
include_directories(${PAM_INCLUDE_DIR})

add_library(pam-vhsm SHARED pam-vhsm.cpp)
add_library(pam-passwd-vhsm SHARED pam-passwd-vhsm.cpp utils.cpp)

target_link_libraries(pam-vhsm vhsmapi ${PROTOBUF_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(pam-passwd-vhsm vhsmapi crypt ${CRYPTO++_LIBRARIES} ${PROTOBUF_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	install(TARGETS pam-vhsm pam-passwd-vhsm DESTINATION /lib/security/)
else()
	install(TARGETS pam-vhsm pam-passwd-vhsm DESTINATION lib)
endif(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
