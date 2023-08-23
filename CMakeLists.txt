cmake_minimum_required(VERSION 3.13)
project(libtlv LANGUAGES CXX)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose Release or Debug" FORCE)
endif()

set(LIBTLV_COMPILE_OPTIONS -Wextra -Wall -pedantic
	$<$<CONFIG:DEBUG>:-Og>
	$<$<CONFIG:RELEASE>:-O3>
)

# Library target
add_library(tlv tlv.cpp include/libtlv/tlv.hpp)
target_include_directories(tlv PUBLIC include)
target_include_directories(tlv PRIVATE include/libtlv)
target_compile_features(tlv PUBLIC cxx_std_11)
target_compile_options(tlv PRIVATE ${LIBTLV_COMPILE_OPTIONS}) 

# Unit Test target
find_library(L_CPPUTEST CppUTest)
add_executable(tlv-test EXCLUDE_FROM_ALL test.cpp)
target_link_libraries(tlv-test tlv ${L_CPPUTEST})
target_compile_options(tlv-test PRIVATE ${LIBTLV_COMPILE_OPTIONS})
add_custom_target(test COMMAND tlv-test) 
