cmake_minimum_required(VERSION 3.5)

# Install libssh if not already installed

project(LatroWeb)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_BUILD_TYPE Debug) # DEBUG

set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(BIN_DIR ${CMAKE_SOURCE_DIR}/bin)
set(KEY_FILE ${CMAKE_SOURCE_DIR}/src/key/dummy_rsa_key)

include_directories(${INCLUDE_DIR})

file(GLOB_RECURSE SOURCES ${SRC_DIR}/*.cpp)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

set(LIBSSH_LIBRARY "/usr/lib/x86_64-linux-gnu/libssh.so")

add_executable(LatroWeb ${SOURCES})

target_link_libraries(LatroWeb ${LIBSSH_LIBRARY})
target_compile_definitions(LatroWeb PRIVATE KEY_FILE="${KEY_FILE}")