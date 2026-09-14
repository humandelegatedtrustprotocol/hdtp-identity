# The Go port of pact-identity: `make test` proves it against the vectors, `make build` produces the
# stdin adapter the JavaScript intrusion driver aims at (`--port go`).
GO ?= go

.PHONY: build test vet
build:
	mkdir -p bin && $(GO) build -o bin/pact-identity-go ./cmd/pact-identity-go
test:
	$(GO) test ./...
vet:
	$(GO) vet ./...
