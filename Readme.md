# libtlv

## Summary
It is a C++ library, which provide X.690 BER TLV implementation.

## Requirements
1. GNU gcc compiler (or clang)
2. GNU Make

## Source code clone
```
git clone <url>
```

## Build
Library uses C++11 features, so the compiler should support that.<br>
Build scripts are written for GNU Make.
### How to build (Make)
Targets:
* static - build static library libtlv.a
* shared - build shared library libtlv.so
* install - install shared library (_/usr/local/lib/_) and header files (_/usr/local/include/_)
* uninstall - remove library and headers
* test - build and run tests (requires CppUTest package)
* clean - cleanup build folder

### Tests
To build tests, CppUTest library is required.

### Install
To install shared library and header files, run "_make install_".

### Uninstall
To remove shared library and header files, run "_make uninstall_".

## Examples
### Headers
See **test.cpp** for usage examples
