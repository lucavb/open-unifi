GO ?= go

.PHONY: build test run provider-build

build:
	$(GO) build ./...

test:
	$(GO) test ./...

run:
	$(GO) run ./cmd/openunifi --listen-inform :8080 --listen-admin :8443

provider-build:
	$(GO) build -o dist/openunifi-tfprovider ./cmd/tfprovider
