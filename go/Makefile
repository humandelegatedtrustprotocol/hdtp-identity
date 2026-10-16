# The Go port of hdtp-identity: `make build` produces the stdin adapter the JavaScript intrusion driver
# aims at (`--port go`). gate.sh vets and tests the port with go itself.
GO ?= go

.PHONY: build
build:
	mkdir -p bin && $(GO) build -o bin/hdtp-identity-go ./cmd/hdtp-identity-go
