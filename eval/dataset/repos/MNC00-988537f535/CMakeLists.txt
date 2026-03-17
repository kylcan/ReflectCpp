cmake_minimum_required(VERSION 3.10)
project(SentinelEval C)

set(CMAKE_C_STANDARD 99)
include_directories(include)

add_library(util STATIC src/util.c)
add_executable(app src/main.c)
target_link_libraries(app util)
