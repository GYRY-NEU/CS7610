RELEASE_FLAGS=-static -s
LINUX_HEADER_x86_64=-I/Volumes/transcend/programs/linux-header/x86_64/include
LINUX_HEADER_arm=-I/Volumes/transcend/programs/linux-header/arm/include
LINUX_HEADER_i386=-I/Volumes/transcend/programs/linux-header/i386/include
VERBOSE=-DCMAKE_VERBOSE_MAKEFILE=ON

CC ?= cc
CXX ?= c++

.PHONY: release debug

release-all: release debug
	echo "build all"

release:
	mkdir -p build-release && \
    cd build-release && \
    conan install .. --profile ../profiles/release-native --build missing && \
    cmake .. -DCMAKE_BUILD_TYPE=Release \
             -DCMAKE_C_COMPILER=${CC}   \
             -DCMAKE_CXX_COMPILER=${CXX} && \
    cmake --build .

debug:
	mkdir -p build-debug && \
    cd build-debug && \
    conan install .. --profile ../profiles/debug --build missing && \
    cmake .. -DCMAKE_BUILD_TYPE=Debug \
             -DCMAKE_C_COMPILER=${CC}   \
             -DCMAKE_CXX_COMPILER=${CXX} && \
    cmake --build .


clean:
	rm -rf build-*
