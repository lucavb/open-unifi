# Agents

## Pipeline

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) is the source of truth for CI. A PR must pass **four** jobs before merge; `docker` runs only on push to `main` after those succeed.

| CI job | What it runs | Local equivalent |
|--------|----------------|------------------|
| `check` | `make check` | `make check` |
| `build` | `go build -v ./...` | `go build ./...` |
| `lint` | golangci-lint **v2.14.0** (workflow pin) | `golangci-lint run ./...` on that version |
| `web` | `npm ci && npm run build` in `web/`, uploads `internal/adminapi/static/dist` as the `console-dist` artifact that `check`/`build`/`lint` download | `make update-frontend` |

**`make check` is not the whole pipeline.** It covers tracked `gofmt`, `go vet`, and `go test -count=1` only. The `lint` job is separate: static analysis (e.g. `unused`) that `vet` does not run.

The admin console is a Vite project in `web/`. Its bundle is **build output, never committed**: `go:embed` needs `internal/adminapi/static/dist` on disk, so the CI `web` job builds it and feeds the Go jobs via the `console-dist` artifact, the Docker image builds it in a `node:24` stage, and the Makefile's Go targets (`build`, `test`, `run`, `check`, `lint`, `hooks-prime`) build it on demand when missing. After editing anything under `web/`, run `make update-frontend` — a raw `go build` on a fresh clone fails until the bundle exists.

Before you say lint is green or the pipeline will pass, run `make check`, `go build ./...`, and `golangci-lint run ./...` (match the workflow version when you can).

There is no committed `.golangci.yml`; CI uses golangci-lint defaults.

## Git hooks (local guardrail)

CI does not run on every laptop commit; **lefthook** is the local gate ([`lefthook.yml`](lefthook.yml)): pre-commit runs `gofmt`, `go vet`, and `golangci-lint` on staged Go files; pre-push runs [`.lefthook/pre-push/ci-parity.sh`](.lefthook/pre-push/ci-parity.sh) for CI-parity checks.

- One-time per clone: `make hooks` (runs [`scripts/install-hook-tools.sh`](scripts/install-hook-tools.sh) — pinned lefthook + golangci-lint **v2.14.0**, then `lefthook install`). In a restricted sandbox (nono blocks the release-download and `go install` hosts) the install fails — run it once from an unrestricted terminal; the `~/go/bin` binaries it installs then run fine from restricted shells (`scripts/hook-env.sh` wires the PATH).
- Before you say a commit is verified or ready to push: `make verify-hooks` ([`scripts/verify-hooks.sh`](scripts/verify-hooks.sh)).
- If `git commit` prints **`Can't find lefthook in PATH`**, hooks did **not** run — run `make hooks`, re-run `make check` / lint as needed, then commit again (do not treat that commit as hook-verified). `LEFTHOOK=0` bypasses hooks on purpose.

`make check` uses `git ls-files '*.go'` for gofmt (not `gofmt -l .`) so gitignored worktree scratch (e.g. `.orca/`) is not scanned.

## Commits (scope)

Long-running branches often mix **audit-run-1 security fixes** with product work in the same packages (`internal/server/server.go` plaintext claim gate, `discovery.go` sightings cap, `internal/app/setinform.go` dial policy, plus their `*_regression_test.go` files).

Before `git add`, inspect `git diff <path>` and **stage security and features in separate commits** unless one change truly depends on the other. Never assume `git add -u` on `internal/server/` is a single story — `handlePlain` and client-session/event wiring are different concerns.

## Review and merges

Before reviewing a diff or resolving a merge/cherry-pick, read [`CODING_STANDARDS.md`](CODING_STANDARDS.md): comments describe current contracts (never history), and after a conflict resolution every structural comment must match the merged code.
