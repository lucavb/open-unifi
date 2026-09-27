GO ?= go

.PHONY: build test run check lint hooks hooks-prime update-frontend web-dist

build: web-dist
	$(GO) build ./...

test: web-dist
	$(GO) test ./...

# Dev convenience: loopback-only admin with a throwaway token; for anything
# exposed use a real --admin-token behind an HTTPS reverse proxy.
run: web-dist
	$(GO) run ./cmd/openunifi --listen-inform :8080 --listen-admin 127.0.0.1:8443 --admin-token dev-local

# CI job "check" only — golangci-lint is a separate workflow job (AGENTS.md).
# Format only the tracked sources: a bare `gofmt -l .` also walks gitignored
# scratch state (worktree caches and the like) and trips on third-party
# generated files that are not part of the module.
check: web-dist
	@out=$$(for f in $$(git ls-files '*.go'); do [ -f "$$f" ] || continue; gofmt -l "$$f"; done | sort -u); if [ -n "$$out" ]; then \
		echo "gofmt needed on:"; echo "$$out"; exit 1; \
	fi
	$(GO) vet ./...
	$(GO) test -count=1 ./...

lint: web-dist
	PATH="$$(go env GOPATH)/bin:$$PATH" golangci-lint run

# Rebuild the admin console's dist bundle (web/ Vite project). The bundle
# is build output, never committed: CI's web job and the Docker image's
# console stage build it the same way (AGENTS.md).
update-frontend:
	cd web && npm ci && npm run build

# go:embed needs internal/adminapi/static/dist on disk, but the bundle is
# never committed (AGENTS.md): the Go targets build it from web/ on demand
# when it is missing. No-op once it exists.
web-dist:
	@if [ ! -f internal/adminapi/static/dist/index.html ]; then \
		echo "web-dist: console bundle missing; building from web/ (needs npm)"; \
		$(MAKE) update-frontend; \
	fi

hooks:
	bash scripts/install-hook-tools.sh

hooks-prime: web-dist
	$(GO) build ./...
	$(GO) test -count=1 ./...
	PATH="$$(go env GOPATH)/bin:$$PATH" golangci-lint run

