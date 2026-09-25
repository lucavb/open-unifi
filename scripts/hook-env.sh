#!/bin/sh
# Sourced by lefthook hook shims (rc: in lefthook.yml) before every hook run.
#
# 1) PATH: put the Go tool bin dirs first so the pinned lefthook/golangci-lint
#    installed by `make hooks` win over any Homebrew versions, and are found at
#    all in environments where GOBIN is not on PATH (e.g. agent sandboxes).
# 2) Caches: when the default Go caches are not writable (restricted sandboxes
#    such as nono grant ~/Library/Caches no access and ~/go read-only), move
#    GOCACHE and GOLANGCI_LINT_CACHE into the session temp dir. GOMODCACHE is
#    left alone: it is only read, which those sandboxes still allow.

_gobin=$(go env GOBIN 2>/dev/null || true)
[ -n "$_gobin" ] || _gobin="$(go env GOPATH 2>/dev/null || true)/bin"
[ -d "$_gobin" ] && PATH="$_gobin:$PATH"

_tools_bin="${TMPDIR:-/tmp}/openunifi-hook-tools"
[ -d "$_tools_bin" ] && PATH="$_tools_bin:$PATH"
export PATH
unset _gobin _tools_bin

_gocache=$(go env GOCACHE 2>/dev/null || true)
mkdir -p "$_gocache" 2>/dev/null || true
if ! [ -w "$_gocache" ]; then
  _root="${TMPDIR:-/tmp}/openunifi-hooks"
  if mkdir -p "$_root/go-build" "$_root/golangci-lint" 2>/dev/null; then
    GOCACHE="$_root/go-build"
    GOLANGCI_LINT_CACHE="$_root/golangci-lint"
    export GOCACHE GOLANGCI_LINT_CACHE
  fi
fi
unset _gocache _root
