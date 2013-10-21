cmake_minimum_required(VERSION 2.8)

project(vhsm)

include_directories(.. ${CMAKE_CURRENT_SOURCE_DIR}/../../netlink_transport ${CMAKE_CURRENT_BINARY_DIR}/../../protocol)

set_source_files_properties(common_impl.c digest_impl.c mac_impl.c key_mgmt_impl.c PROPERTIES LANGUAGE CXX )

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
add_library(vhsmapi SHARED transport_impl.cpp common_impl.c digest_impl.c mac_impl.c key_mgmt_impl.c)
target_link_libraries(vhsmapi "-Wl,--whole-archive" VhsmMessageTransport vhsm_transport.pb "-Wl,--no-whole-archive")

install(TARGETS vhsmapi DESTINATION lib)
