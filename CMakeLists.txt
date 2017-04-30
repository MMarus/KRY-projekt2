cmake_minimum_required(VERSION 3.6)
project(KRY_projekt2)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-lssl -lcrypto")
set(SOURCE_FILES main.cpp Connection.cpp Connection.h openssl-bio-fetch.cpp)
add_executable(KRY_projekt2 ${SOURCE_FILES})