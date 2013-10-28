
# all packages
add_custom_target(pkg)

#vhsm-client
set(BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/client)
configure_file(client/CMakeLists.txt.in ${BUILD_DIR}/CMakeLists.txt @ONLY)
add_custom_target(
    vhsm-client
    rm -f ${BUILD_DIR}/CPackConfig.cmake
    COMMAND ${CMAKE_COMMAND} .
    COMMAND ${CMAKE_CPACK_COMMAND}
    WORKING_DIRECTORY ${BUILD_DIR}
)
add_dependencies(vhsm-client vhsmapi vhsm_user_admin)
if(BUILD_pam)
    add_dependencies(vhsm-client pam-vhsm)
endif()

#vhsm-host
set(BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/host)
configure_file(host/CMakeLists.txt.in ${BUILD_DIR}/CMakeLists.txt @ONLY)
add_custom_target(
    vhsm-host
    rm -f ${BUILD_DIR}/CPackConfig.cmake
    COMMAND ${CMAKE_COMMAND} .
    COMMAND ${CMAKE_CPACK_COMMAND}
    WORKING_DIRECTORY ${BUILD_DIR}
)
add_dependencies(vhsm-host transport_module vhsm vhsm_admin vhsm_transport.pb)

#vhsm-server
set(BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/server)
configure_file(server/CMakeLists.txt.in ${BUILD_DIR}/CMakeLists.txt @ONLY)
add_custom_target(
    vhsm-server
    rm -f ${BUILD_DIR}/CPackConfig.cmake
    COMMAND ${CMAKE_COMMAND} .
    COMMAND ${CMAKE_CPACK_COMMAND}
    WORKING_DIRECTORY ${BUILD_DIR}
)
add_dependencies(vhsm-server transport_module vhsm vhsm_transport.pb)

add_dependencies(pkg vhsm-client vhsm-host vhsm-server)

