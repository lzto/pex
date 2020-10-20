cmake_minimum_required(VERSION 3.4.3)
cmake_policy(SET CMP0074 OLD)
project(pex)

set(CMAKE_CXX_STANDARD 14)

find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})


list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/libsvf/include
                    ${CMAKE_CURRENT_BINARY_DIR}/libsvf/include)


                  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fPIC -Wall")

add_subdirectory(libsvf/lib)
add_subdirectory(gatlin)

