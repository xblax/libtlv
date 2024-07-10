# libtlv

## Summary
This is a C++ library that provides X.690 BER TLV parsing, building and encoding.

This a fork of [toumilov/libtlv](https://github.com/toumilov/libtlv/).<br>
The API and library semantics might change in the future. Use at your own risk.

## Requirements
1. GNU gcc compiler (or clang)
2. CMake

## Build and use
Library uses C++11 features, so the compiler should support that.<br>
Build system is CMake. The CMake project provides a static library target for libtlv.a

To use the library, it's recommended to include it as subdirectory into an existing CMake project.

### Tests
To build the test target, CppUTest library is required.

## Examples
### Headers
See **test.cpp** for usage examples
