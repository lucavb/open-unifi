GO ?= go

.PHONY: build test run provider-build check acceptance

build:
	$(GO) build ./...

test:
	$(GO) test ./...

# Dev convenience: loopback-only admin with a throwaway token; for anything
# exposed use a real --admin-token behind an HTTPS reverse proxy.
run:
	$(GO) run ./cmd/openunifi --listen-inform :8080 --listen-admin 127.0.0.1:8443 --admin-token dev-local

provider-build:
	$(GO) build -o dist/openunifi-tfprovider ./cmd/tfprovider

# The module gate: everything CI (and the morning acceptance checklist) runs.
# Format only the tracked sources: a bare `gofmt -l .` also walks gitignored
# scratch state (worktree caches and the like) and trips on third-party
# generated files that are not part of the module.
check:
	@out=$$(gofmt -l $$(git ls-files '*.go')); if [ -n "$$out" ]; then \
		echo "gofmt needed on:"; echo "$$out"; exit 1; \
	fi
	$(GO) vet ./...
	$(GO) test -count=1 ./...

# Hermetic black-box Terraform acceptance suite. The test itself is gated by
# TF_ACC=1; this target makes that opt-in explicit and keeps all artifacts in
# the test's temporary root.
acceptance:
	TF_ACC=1 $(GO) test -tags acceptance -count=1 ./acceptance -v
