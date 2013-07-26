cmake_minimum_required(VERSION 2.8)

project(vhsm)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../netlink_transport ${CMAKE_CURRENT_BINARY_DIR}/../protocol)

set(VHSM_LIBRARIES VhsmStorage ${CRYPTO++_LIBRARIES} ${SQLITE3_LIBRARIES})
set(TRANSPORT_LIBRARIES VhsmMessageTransport vhsm_transport.pb ${PROTOBUF_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})

add_library(VhsmStorage STATIC VhsmStorage.cpp)

add_executable(vhsm_admin vhsm_admin.cpp)
add_dependencies(vhsm_admin VhsmStorage)
target_link_libraries(vhsm_admin ${VHSM_LIBRARIES})

add_library(VhsmClass STATIC vhsm.cpp MessageHandler.cpp)

add_executable(vhsm vhsm_app.cpp)
add_dependencies(vhsm VhsmClass VhsmStorage)
target_link_libraries(vhsm VhsmClass ${VHSM_LIBRARIES} ${TRANSPORT_LIBRARIES})

install(TARGETS vhsm vhsm_admin DESTINATION bin)
