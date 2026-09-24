# Agents

## Pipeline

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) is the source of truth for CI. A PR must pass **three** jobs before merge; `docker` runs only on push to `main` after those succeed.

| CI job | What it runs | Local equivalent |
|--------|----------------|------------------|
| `check` | `make check` | `make check` |
| `build` | `go build -v ./...` | `go build ./...` |
| `lint` | golangci-lint **v2.11.4** (workflow pin) | `golangci-lint run ./...` on that version |

**`make check` is not the whole pipeline.** It covers tracked `gofmt`, `go vet`, and `go test -count=1` only. The `lint` job is separate: static analysis (e.g. `unused`) that `vet` does not run.

Before you say lint is green or the pipeline will pass, run `make check`, `go build ./...`, and `golangci-lint run ./...` (match the workflow version when you can).

There is no committed `.golangci.yml`; CI uses golangci-lint defaults.
