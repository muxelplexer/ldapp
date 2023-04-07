cmake_minimum_required(VERSION 3.24)
project(ldapp
        VERSION 0.1.0
)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(OpenLdap REQUIRED)

add_subdirectory(src)