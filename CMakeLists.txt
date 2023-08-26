cmake_minimum_required(VERSION 2.0)
project (ipsnect)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -static-libstdc++")

file(GLOB _SRC
    "*.cpp"
)

add_executable(ipsnect
  ${_SRC}
)
