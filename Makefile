BINARY  := pler
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -X main.version=$(VERSION)
DIST    := dist

.PHONY: all generate build test test-integration release clean

all: build

## generate: compile eBPF C → Go bindings (requires clang + libbpf-dev)
generate: internal/bpf/vmlinux.h
	go generate ./internal/bpf/...

internal/bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

## build: compile the pler binary (runs generate first)
build: generate
	mkdir -p $(DIST)
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY) ./cmd/pler/

## test: run unit tests (no root required)
test:
	CGO_ENABLED=0 go test ./internal/... -v -count=1

## test-integration: run integration tests (requires root + BPF caps)
test-integration: build
	sudo CGO_ENABLED=0 go test -tags integration ./test/integration/... -v -count=1

## release: build binary + .deb + .rpm + .tar.gz (requires nfpm)
release: build
	nfpm package --config packaging/nfpm.yaml --packager deb --target $(DIST)/
	nfpm package --config packaging/nfpm.yaml --packager rpm --target $(DIST)/
	tar czf $(DIST)/$(BINARY)_$(VERSION)_linux_amd64.tar.gz \
	    -C $(DIST) $(BINARY)
	@echo ""
	@echo "Artifacts:"
	@ls -lh $(DIST)/

## clean: remove generated and built files
clean:
	rm -rf $(DIST)/
	rm -f internal/bpf/execve_bpf*.go internal/bpf/execve_bpf*.o
	rm -f internal/bpf/vmlinux.h
