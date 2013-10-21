cmake_minimum_required(VERSION 2.8)

project(vhsm)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
add_library(VhsmMessageTransport VhsmMessageTransport.h VhsmMessageTransport.cpp)
set(MODULE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/kernel/vhsm_transport.ko 
	${CMAKE_CURRENT_SOURCE_DIR}/kernel/vhsm_transport.mod.c
	${CMAKE_CURRENT_SOURCE_DIR}/kernel/vhsm_transport.mod.o
	${CMAKE_CURRENT_SOURCE_DIR}/kernel/vhsm_transport.o
	${CMAKE_CURRENT_SOURCE_DIR}/kernel/modules.order
	${CMAKE_CURRENT_SOURCE_DIR}/kernel/Module.symvers
	${CMAKE_CURRENT_SOURCE_DIR}/kernel/.vhsm_transport.o.cmd
	${CMAKE_CURRENT_SOURCE_DIR}/kernel/.vhsm_transport.ko.cmd
	${CMAKE_CURRENT_SOURCE_DIR}/kernel/.vhsm_transport.mod.o.cmd
)

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${MODULE_FILES}")
