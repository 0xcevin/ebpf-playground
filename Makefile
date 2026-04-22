.PHONY: all generate build clean run

BINARY := ebpf-tracepoint

all: build

generate:
	go generate ./...

build: generate
	CGO_ENABLED=0 go build -ldflags '-s -w' -o $(BINARY) .
	@echo "Build complete: $(BINARY)"

clean:
	rm -f $(BINARY)
	rm -f trace_bpf*.go
	rm -f trace_bpf*.o

run: build
	sudo ./$(BINARY)
