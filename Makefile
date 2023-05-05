
CURRENT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
INSTALL_HEADERS_DIR := /usr/local/include/
INSTALL_LIB_DIR := /usr/local/lib/
SHARED_LIB := libtlv.so
STATIC_LIB := libtlv.a
OBJ_FILE := tlv.o
CFLAGS := -fno-rtti -fPIC --std=c++11
AR = ar
CXX = g++
#CXX = clang++

.PHONY: all static shared install uninstall test clean

all: static shared

$(OBJ_FILE): $(CURRENT_DIR)tlv.cpp
	$(CXX) -I $(CURRENT_DIR) $(CFLAGS) -g -c -o $@ $<

static: $(OBJ_FILE)
	$(AR) rcs $(STATIC_LIB) $^

shared: $(OBJ_FILE)
	$(CXX) $^ -shared -o $(SHARED_LIB)

install: shared
	@echo Copying headers
	cp $(CURRENT_DIR)tlv.hpp $(INSTALL_HEADERS_DIR)
	@echo Copying library
	cp $(CURRENT_DIR)$(SHARED_LIB) $(INSTALL_LIB_DIR)
	@echo Done

uninstall:
	rm $(INSTALL_HEADERS_DIR)tlv.hpp
	rm $(INSTALL_LIB_DIR)$(SHARED_LIB)
	@echo Done

# requires cpputest
# apt install cpputest
test: static $(CURRENT_DIR)test.cpp
	$(CXX) -I $(CURRENT_DIR) -g -c $(CURRENT_DIR)test.cpp
	$(CXX) test.o -L $(CURRENT_DIR) -l:$(STATIC_LIB) -lCppUTest -lCppUTestExt -o unittests
	@echo Running tests...
	@exec $(CURRENT_DIR)unittests -v

clean:
	rm -rf $(CURRENT_DIR)$(STATIC_LIB)
	rm -rf $(CURRENT_DIR)$(SHARED_LIB)
	rm -rf $(CURRENT_DIR)$(OBJ_FILE)
	rm -rf $(CURRENT_DIR)test.o
	rm -rf $(CURRENT_DIR)unittests
