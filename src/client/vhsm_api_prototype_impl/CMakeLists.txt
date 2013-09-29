cmake_minimum_required(VERSION 2.8)

project(vhsm)

# With openssl engine it should be compiled with fPIC option

include_directories(.. ${CMAKE_CURRENT_SOURCE_DIR}/../../netlink_transport ${CMAKE_CURRENT_BINARY_DIR}/../../protocol)

set_source_files_properties(common_impl.c digest_impl.c mac_impl.c key_mgmt_impl.c PROPERTIES LANGUAGE CXX )

add_library(vhsmapi transport_impl.cpp common_impl.c digest_impl.c mac_impl.c key_mgmt_impl.c)
target_link_libraries(vhsmapi VhsmMessageTransport vhsm_transport.pb)

install(TARGETS vhsmapi DESTINATION lib)
