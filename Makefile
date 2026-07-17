# cal-gateway — developer convenience targets.
# The whole stack is pure Go: build with CGO disabled (a static binary, and it
# sidesteps a toolchain gotcha where a stray `as` on PATH breaks runtime/cgo).

BINARY      ?= cal-gateway
PKG         ?= ./cmd/cal-gateway
GOFLAGS     ?=
CGO_ENABLED ?= 0
export CGO_ENABLED

.PHONY: build test vet fmt lint run help

## build: compile a static binary
build:
	CGO_ENABLED=$(CGO_ENABLED) go build $(GOFLAGS) -o $(BINARY) $(PKG)

## test: run unit tests (mocked, no network; live tests are opt-in — see CONTRIBUTING.md)
test:
	go test ./...

## vet: run go vet
vet:
	go vet ./...

## fmt: format all Go sources in place
fmt:
	gofmt -w .

## lint: fail if any Go source is not gofmt-clean
lint:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
		echo "gofmt needs to run on:"; echo "$$out"; exit 1; \
	fi

## run: build then run `serve` against ./config.toml
run: build
	./$(BINARY) serve -config config.toml

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
