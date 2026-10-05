#!/bin/sh
# Relocates GOCACHE and GOLANGCI_LINT_CACHE to the session temp dir when the
# default Go caches are not writable (restricted sandboxes such as nono grant
# ~/Library/Caches no access and ~/go read-only). GOMODCACHE is left alone: it
# is only read, which those sandboxes still allow.
#
# Idempotent and silent: no-op when the defaults are writable or GOCACHE is
# already exported and writable.

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
