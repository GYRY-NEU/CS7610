cmake_minimum_required(VERSION 3.5.1)
#avoid cmake adds -Wl,-search_paths_first that makes mac compiled binary segmentation fault
set(HAVE_FLAG_SEARCH_PATHS_FIRST 0)

project(run)

set(CMAKE_CXX_STANDARD 17)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)

set(Boost_INSTALL_DIR ${CONAN_BOOST_ROOT})

conan_basic_setup()

set(CROSS_LINKER_FLAGS "-static-libgcc -static-libstdc++")

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CROSS_LINKER_FLAGS "-static")
endif()

add_executable(run main.cpp)

target_link_libraries(run ${CONAN_LIBS} ${CROSS_LINKER_FLAGS})

IF ("${CMAKE_SYSTEM_NAME}" MATCHES "Windows")
   target_link_libraries(run ws2_32 wsock32)
ENDIF ()
