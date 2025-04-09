cmake_minimum_required(VERSION 3.10)

# Install libssh if not already installed

project(LatroWeb)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_BUILD_TYPE Debug) # DEBUG

set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(BIN_DIR ${CMAKE_SOURCE_DIR}/bin)
set(KEY_FILE ${CMAKE_SOURCE_DIR}/src/key/dummy_rsa_key)
set(JSON_FILE ${CMAKE_SOURCE_DIR}/meta.json)
set(LOG_DIR ${CMAKE_SOURCE_DIR}/Logs/)

#set(LIBSSH_LIBRARY "/usr/lib/x86_64-linux-gnu/libssh.so")
set(NLOHMANN_JSON_DIR "/usr/local/include/nlohmann")


include_directories(${INCLUDE_DIR})
include_directories(${NLOHMANN_JSON_DIR})

file(GLOB_RECURSE SOURCES ${SRC_DIR}/*.cpp)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})


add_executable(LatroWeb ${SOURCES})

target_link_libraries(LatroWeb ${LIBSSH_LIBRARY})
target_compile_definitions(LatroWeb PRIVATE KEY_FILE="${KEY_FILE}" JSON_FILE="${JSON_FILE}" LOG_DIR="${LOG_DIR}")