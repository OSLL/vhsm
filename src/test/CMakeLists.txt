cmake_minimum_required(VERSION 2.8)

project(vhsm)

set(LIBS utils vhsmapi ${PROTOBUF_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../client/vhsm_api_prototype)

add_library(utils STATIC utils.cpp)
add_executable(test_create_key test_create_key.cpp)
add_executable(test_digest test_digest.cpp)
add_executable(test_hmac test_hmac.cpp)
add_executable(test_gen_keys test_gen_keys.cpp)
add_executable(test_enum_keys test_enum_keys.cpp)

target_link_libraries(test_create_key ${LIBS})
target_link_libraries(test_digest ${LIBS})
target_link_libraries(test_hmac ${LIBS})
target_link_libraries(test_gen_keys ${LIBS})
target_link_libraries(test_enum_keys ${LIBS})

install(TARGETS test_create_key test_digest test_hmac test_gen_keys test_enum_keys DESTINATION bin/tests)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh DESTINATION bin/tests)

add_subdirectory(unit_tests)
