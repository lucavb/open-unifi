# Agents

## Pipeline

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) is the source of truth for CI. A PR must pass **four** jobs before merge; `docker` runs only on push to `main` after those succeed.

| CI job | What it runs | Local equivalent |
|--------|----------------|------------------|
| `check` | `make check` | `make check` |
| `build` | `go build -v ./...` | `go build ./...` |
| `lint` | golangci-lint **v2.11.4** (workflow pin) | `golangci-lint run ./...` on that version |
| `web` | `npm ci && npm run build` in `web/`, uploads `internal/adminapi/static/dist` as the `console-dist` artifact that `check`/`build`/`lint` download | `make update-frontend` |

**`make check` is not the whole pipeline.** It covers tracked `gofmt`, `go vet`, and `go test -count=1` only. The `lint` job is separate: static analysis (e.g. `unused`) that `vet` does not run.

The admin console is a Vite project in `web/`. Its bundle is **build output, never committed**: `go:embed` needs `internal/adminapi/static/dist` on disk, so the CI `web` job builds it and feeds the Go jobs via the `console-dist` artifact, the Docker image builds it in a `node:24` stage, and the Makefile's Go targets (`build`, `test`, `run`, `check`, `lint`, `hooks-prime`) build it on demand when missing. After editing anything under `web/`, run `make update-frontend` — a raw `go build` on a fresh clone fails until the bundle exists.

Before you say lint is green or the pipeline will pass, run `make check`, `go build ./...`, and `golangci-lint run ./...` (match the workflow version when you can).

There is no committed `.golangci.yml`; CI uses golangci-lint defaults.
