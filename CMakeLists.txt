cmake_minimum_required(VERSION 3.18...3.24)

# Read the AGENT_SOFTWARE_VERSION from version.h file
set(VERSION_REGEX "^#define AGENT_SOFTWARE_VERSION[ ]+\"([0-9.]+)\"$")
file(STRINGS "include/obuspa/core/version.h" VERSION_STRING REGEX ${VERSION_REGEX})
string(REGEX REPLACE ${VERSION_REGEX} "\\1" VERSION_STRING "${VERSION_STRING}")

project(obuspa
  DESCRIPTION "OB-USP Agent"
  VERSION ${VERSION_STRING}
  HOMEPAGE_URL "https://github.com/BroadbandForum/obuspa/"
  LANGUAGES C)

include(GNUInstallDirs)

set(OBUSPA_LOCAL_STATE_DIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LOCALSTATEDIR}/obuspa)
message(STATUS "OBUSPA_LOCAL_STATE_DIR: ${OBUSPA_LOCAL_STATE_DIR}")

option(ENABLE_STOMP "enable STOMP MTP support" ON)
option(ENABLE_MQTT "enable MQTT MTP support" ON)
option(ENABLE_COAP "enable CoAP MTP support" ON)
option(ENABLE_WEBSOCKETS "enable WebSockets MTP support" ON)
option(ENABLE_UDS "enable UDS MTP support" ON)
message(STATUS "MTP to support: STOMP:${ENABLE_STOMP} MQTT:${ENABLE_MQTT} COAP:${ENABLE_COAP} WEBSOCKETS:${ENABLE_WEBSOCKETS} UDS:${ENABLE_UDS}")

add_executable(obuspa
    src/core/main.c)

set(LOCAL_STATE_DIR_DEFINE_STR ${OBUSPA_LOCAL_STATE_DIR})
set(DISABLE_STOMP_DEFINE "")
set(ENABLE_COAP_DEFINE "")
set(ENABLE_MQTT_DEFINE "")
set(ENABLE_WEBSOCKETS_DEFINE "")
set(ENABLE_UDS_DEFINE "")
set(REMOVE_DEVICE_BULKDATA_DEFINE "")

if(NOT ENABLE_STOMP)
  set(DISABLE_STOMP_DEFINE "#define DISABLE_STOMP 1")
endif()

if(ENABLE_COAP)
  set(ENABLE_COAP_DEFINE "#define ENABLE_COAP 1")
endif()

if(ENABLE_MQTT)
  set(ENABLE_MQTT_DEFINE "#define ENABLE_MQTT 1")
endif()

if(ENABLE_WEBSOCKETS)
  set(ENABLE_WEBSOCKETS_DEFINE "#define ENABLE_WEBSOCKETS 1")
endif()

if(ENABLE_UDS)
  set(ENABLE_UDS_DEFINE "#define ENABLE_UDS 1")
endif()

if(REMOVE_DEVICE_BULKDATA)
  set(REMOVE_DEVICE_BULKDATA_DEFINE "#define REMOVE_DEVICE_BULKDATA 1")
endif()

configure_file(
  ${PROJECT_SOURCE_DIR}/include/obuspa/vendor_options.h.in
  ${CMAKE_BINARY_DIR}/include/obuspa/vendor_options.h
  @ONLY
)

target_include_directories(obuspa
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include)

target_link_libraries(obuspa
  PRIVATE
    vendor
    core)

add_subdirectory(src/libjson)
add_subdirectory(src/protobuf-c)
add_subdirectory(src/vendor)
add_subdirectory(src/core)

# Install executable and create working directory.
# This depends on your prefix setting (default CMAKE_INSTALL_PREFIX=/usr/local/)
# - Default executable path: /usr/local/bin/obuspa
# - Default database path: /usr/local/var/obuspa/usp.db
install(TARGETS obuspa RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY DESTINATION ${OBUSPA_LOCAL_STATE_DIR})
