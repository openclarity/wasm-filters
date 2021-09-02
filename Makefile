# Go parameters
    GOCMD=go
	TINYGOCMD=tinygo
	TINYGOBUILD=$(TINYGOCMD) build
	GOCLEAN=$(GOCMD) clean
	GOTEST=$(GOCMD) test
	GOGET=$(GOCMD) get
	BINARY_NAME=http-trace-filter.wasm

all: build

build: build_filter

build_filter:
	mkdir -p bin
	$(TINYGOBUILD) -o ./bin/$(BINARY_NAME)  -scheduler=none -target=wasi src/trace/main.go

.PHONY: docker_build
docker_build:
	@echo "Running make docker_build"
	@DOCKER_BUILDKIT=1 docker build --file docker/Dockerfile.build.local --target bin --output bin/ .

clean:
	$(GOCLEAN)
	rm -f ./bin/*.wasm
