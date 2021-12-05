RELEASE_FLAGS=-static -s
VERBOSE=-DCMAKE_VERBOSE_MAKEFILE=ON

CC ?= cc
CXX ?= c++

.PHONY: release debug from-docker

from-docker:
	docker build -t hare1039/final:0.0.1 .;
	id=$$(docker create hare1039/final:0.0.1); \
	docker cp $$id:/final/build-release/bin/run .; \
	docker rm -v $$id; \
	echo 'binary gerenated to ./run';

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
