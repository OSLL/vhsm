cmake_minimum_required(VERSION 2.8)

project(vhsm)

set(DEF_LIBS VhsmMessageTransport vhsm_transport.pb ${PROTOBUF_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${CRYPTO++_LIBRARIES} ${SQLITE3_LIBRARIES} ${CPPUNIT_LIBRARY})

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../vhsm/ ${CMAKE_CURRENT_SOURCE_DIR}/../../netlink_transport/ ${CMAKE_CURRENT_BINARY_DIR}/../../protocol)

add_executable(mh_tests
	mh_tests.cpp
	vhsm_mock.cpp
	MessageHandlerTest.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/../../vhsm/MessageHandler.cpp
)

target_link_libraries(mh_tests VhsmStorage ${DEF_LIBS})

add_executable(vhsm_tests
	vhsm_tests.cpp
	vhsm_storage_mock.cpp
	VhsmTest.cpp
)

target_link_libraries(vhsm_tests VhsmClass ${DEF_LIBS})

add_executable(storage_tests
	storage_tests.cpp
	VhsmStorageTest.cpp
)

target_link_libraries(storage_tests VhsmStorage ${CRYPTO++_LIBRARIES} ${SQLITE3_LIBRARIES} ${CPPUNIT_LIBRARY})

install(TARGETS mh_tests vhsm_tests storage_tests DESTINATION bin/tests)
