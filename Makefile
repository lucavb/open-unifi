GO ?= go

.PHONY: build test run check

build:
	$(GO) build ./...

test:
	$(GO) test ./...

# Dev convenience: loopback-only admin with a throwaway token; for anything
# exposed use a real --admin-token behind an HTTPS reverse proxy.
run:
	$(GO) run ./cmd/openunifi --listen-inform :8080 --listen-admin 127.0.0.1:8443 --admin-token dev-local

# CI job "check" only — golangci-lint is a separate workflow job (AGENTS.md).
# Format only the tracked sources: a bare `gofmt -l .` also walks gitignored
# scratch state (worktree caches and the like) and trips on third-party
# generated files that are not part of the module.
check:
	@out=$$(for f in $$(git ls-files '*.go'); do [ -f "$$f" ] || continue; gofmt -l "$$f"; done | sort -u); if [ -n "$$out" ]; then \
		echo "gofmt needed on:"; echo "$$out"; exit 1; \
	fi
	$(GO) vet ./...
	$(GO) test -count=1 ./...

