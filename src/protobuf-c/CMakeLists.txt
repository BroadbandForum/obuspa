add_library(protobuf-c
    usp-msg.pb-c.c
    usp-record.pb-c.c
    protobuf-c.c)

target_include_directories(protobuf-c
  PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include)  # Because <protobuf-c/protobuf-c.h> is search from parent folder by USP pb files
