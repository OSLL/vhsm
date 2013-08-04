cmake_minimum_required(VERSION 2.8)

project(vhsm)

set(LIBS vhsmapi ${PROTOBUF_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${CRYPTO++_LIBRARIES} ${CPPUNIT_LIBRARY})

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../client)

add_executable(test_login test_login.cpp)
add_executable(test_key_mgmt test_key_mgmt.cpp)
#add_executable(test_digest test_digest.cpp)
add_executable(test_hmac test_hmac.cpp)

target_link_libraries(test_login ${LIBS})
target_link_libraries(test_key_mgmt ${LIBS})
#target_link_libraries(test_digest ${LIBS})
target_link_libraries(test_hmac ${LIBS})

install(TARGETS test_login test_key_mgmt test_hmac DESTINATION bin/tests)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh DESTINATION bin/tests)

add_subdirectory(unit_tests)
