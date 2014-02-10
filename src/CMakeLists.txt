cmake_minimum_required (VERSION 2.6)
project (std_crypto)
#find_package(libgcrypt REQUIRED)

include_directories(../include)


add_definitions(-std=c++11 -Wall -Wextra)
add_executable(test_hash test_hash.cpp)
target_link_libraries (test_hash gcrypt)

enable_testing()
add_test(test_hash test_hash)

