cmake_minimum_required(VERSION 3.14)
project(libtlv LANGUAGES CXX)

if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(LIBTLV_MASTER_PROJECT ON)
else()
    set(LIBTLV_MASTER_RPOJECT OFF)
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose Release or Debug" FORCE)
endif()

set(LIBTLV_COMPILE_OPTIONS -Wextra -Wall -pedantic
    $<$<CONFIG:DEBUG>:-Og>
    $<$<CONFIG:RELEASE>:-O3>
)

# Library target
add_library(tlv tlv.cpp include/libtlv/tlv.hpp)
add_library(libtlv::tlv ALIAS tlv)
target_include_directories(tlv INTERFACE include)
target_include_directories(tlv PRIVATE include/libtlv)

target_compile_features(tlv PUBLIC cxx_std_17)
target_compile_options(tlv PRIVATE ${LIBTLV_COMPILE_OPTIONS})

# additional targets are only available if libtlv is the master project
if(LIBTLV_MASTER_PROJECT)

    # test target is only availbale if CppUTest was found
    find_library(L_CPPUTEST CppUTest)
    if(L_CPPUTEST)
        add_executable(tlv-test EXCLUDE_FROM_ALL test.cpp)
        target_link_libraries(tlv-test tlv ${L_CPPUTEST})
        target_compile_options(tlv-test PRIVATE ${LIBTLV_COMPILE_OPTIONS})
        add_custom_target(unittest COMMAND tlv-test)
    endif()

    # tlvutil cmdline tool
    include(FetchContent)
    FetchContent_Declare(
        cli11_proj
        QUIET
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG v2.4.2
    )
    FetchContent_MakeAvailable(cli11_proj)
    add_executable(tlvutil tlvutil.cpp)
    target_link_libraries(tlvutil tlv CLI11::CLI11)
    target_compile_options(tlvutil PRIVATE ${LIBTLV_COMPILE_OPTIONS})

endif()
