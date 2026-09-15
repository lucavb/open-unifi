GO ?= go

.PHONY: build test run provider-build check

build:
	$(GO) build ./...

test:
	$(GO) test ./...

run:
	$(GO) run ./cmd/openunifi --listen-inform :8080 --listen-admin :8443

provider-build:
	$(GO) build -o dist/openunifi-tfprovider ./cmd/tfprovider

# The module gate: everything CI (and the morning acceptance checklist) runs.
check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then \
		echo "gofmt needed on:"; echo "$$out"; exit 1; \
	fi
	$(GO) vet ./...
	$(GO) test -count=1 ./...
