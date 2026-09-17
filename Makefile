GO ?= go

.PHONY: build test run provider-build check acceptance

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

# Hermetic black-box Terraform acceptance suite. The test itself is gated by
# TF_ACC=1; this target makes that opt-in explicit and keeps all artifacts in
# the test's temporary root.
acceptance:
	TF_ACC=1 $(GO) test -tags acceptance -count=1 ./acceptance -v
