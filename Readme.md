# libtlv

## Summary
This is a C++ library that provides X.690 BER TLV parsing, building and encoding.

This fork of [toumilov/libtlv](https://github.com/toumilov/libtlv/) is still under development -- breaking changes may be introduced at any time.

## Requirements
1. GNU gcc compiler (or clang)
2. CMake

## Source code clone
```
git clone <url>
```

## Build and use
Library uses C++11 features, so the compiler should support that.<br>
Build system is CMake. The CMake project provides a static library target for libtlv.a

To use the library, it's recommended to include it as subdirectory into an existing CMake project.

### Tests
To build the test target, CppUTest library is required.

## Examples
### Headers
See **test.cpp** for usage examples
