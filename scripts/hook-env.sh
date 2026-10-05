#!/bin/sh
# Sourced by lefthook hook shims (rc: in lefthook.yml) before every hook run.
#
# 1) PATH: put the Go tool bin dirs first so the pinned lefthook/golangci-lint
#    installed by `make hooks` win over any Homebrew versions, and are found at
#    all in environments where GOBIN is not on PATH (e.g. agent sandboxes).
# 2) Caches: the sandbox-safe Go cache fallback lives in scripts/dev-env.sh.

_gobin=$(go env GOBIN 2>/dev/null || true)
[ -n "$_gobin" ] || _gobin="$(go env GOPATH 2>/dev/null || true)/bin"
[ -d "$_gobin" ] && PATH="$_gobin:$PATH"

_tools_bin="${TMPDIR:-/tmp}/openunifi-hook-tools"
[ -d "$_tools_bin" ] && PATH="$_tools_bin:$PATH"
export PATH
unset _gobin _tools_bin

_devroot=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [ -n "$_devroot" ]; then
  . "$_devroot/scripts/dev-env.sh"
fi
unset _devroot
