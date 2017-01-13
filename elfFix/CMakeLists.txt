cmake_minimum_required (VERSION 2.6)
project (elfFix)

set(CMAKE_CXX_FLAGS "-g -Wall -Wextra -Wshadow")
add_executable(${PROJECT_NAME} elfFix.cpp)