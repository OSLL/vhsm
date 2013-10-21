cmake_minimum_required(VERSION 2.8)

project(vhsm)

add_custom_command(
	OUTPUT vhsm_transport.pb.h vhsm_transport.pb.cc
	COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} vhsm_transport.proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
	DEPENDS vhsm_transport.proto
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

set_source_files_properties(vhsm_transport.pb.h vhsm_transport.pb.cc PROPERTIES GENERATED TRUE)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
add_library(vhsm_transport.pb vhsm_transport.pb.h vhsm_transport.pb.cc)

