cmake_minimum_required(VERSION 2.8)

project(vhsm)

include_directories(..)

add_executable(vhsm_user_admin vhsm_admin.cpp)

target_link_libraries(vhsm_user_admin vhsmapi ${PROTOBUF_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})

install(TARGETS vhsm_user_admin DESTINATION bin)
