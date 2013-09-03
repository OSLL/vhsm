cmake_minimum_required(VERSION 2.8)

project(vhsm)

include_directories(../vhsm_api_prototype ${CMAKE_CURRENT_BINARY_DIR}/../../protocol)

add_executable(test_app test_app.cpp)

target_link_libraries(test_app vhsmapi ${PROTOBUF_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} vhsm_transport.pb)
