.PHONY: all generate build build-debug clean run

BINARY := ebpf-tracepoint

VERSION      := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME   := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
BUILD_OS     := $(shell go env GOOS)
BUILD_ARCH   := $(shell go env GOARCH)
BUILD_KERNEL := $(shell uname -r)
GO_VERSION   := $(shell go version | cut -d' ' -f3)

LDFLAGS_BASE := -X main.Version=$(VERSION) \
                -X main.BuildTime=$(BUILD_TIME) \
                -X main.BuildOS=$(BUILD_OS) \
                -X main.BuildArch=$(BUILD_ARCH) \
                -X main.BuildKernel=$(BUILD_KERNEL) \
                -X main.GoVersion=$(GO_VERSION)

LDFLAGS_RELEASE := -s -w $(LDFLAGS_BASE)
LDFLAGS_DEBUG   := $(LDFLAGS_BASE)

all: build

generate:
	go generate ./...

build: generate
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS_RELEASE)' -o $(BINARY) .
	@echo "Build complete: $(BINARY)"

build-debug: generate
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS_DEBUG)' -o $(BINARY)-debug .
	@echo "Build complete: $(BINARY)-debug"

clean:
	rm -f $(BINARY)
	rm -f $(BINARY)-debug
	rm -f trace_bpf*.go
	rm -f trace_bpf*.o

run: build
	sudo ./$(BINARY)
