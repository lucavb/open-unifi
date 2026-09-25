#!/usr/bin/env bash
# Installs the pinned hook toolchain (lefthook v2.1.14 + golangci-lint v2.11.4,
# matching .github/workflows/ci.yml) and wires the git hooks via
# `lefthook install` (pre-commit jobs + the pre-push script job, both defined
# in lefthook.yml and .lefthook/).
#
# Primary path: release binaries from github.com (fast, sha256-verified).
# Fallback:     `go install` of the same pinned versions via the Go module
#               proxy, for restricted networks where GitHub release assets are
#               blocked. Needs Go >= 1.26.
# Sandbox-safe: if the default GOBIN / module / build caches are not writable
#               (e.g. the nono sandbox grants ~/go read-only), installs and
#               caches are relocated to the session temp dir instead of failing.
#               Restricted shells still read and run binaries installed to
#               ~/go/bin from an unrestricted terminal, so a one-time normal
#               `make hooks` covers every environment on the machine.

set -euo pipefail

LEFTHOOK_VERSION="v2.1.14"
GOLANGCI_LINT_VERSION="v2.11.4"

fallback_root="${TMPDIR:-/tmp}/openunifi-hooks"
fallback_bin="${TMPDIR:-/tmp}/openunifi-hook-tools"

default_gobin="$(go env GOBIN 2>/dev/null || true)"
[ -n "$default_gobin" ] || default_gobin="$(go env GOPATH 2>/dev/null)/bin"

# find_tool <name>: first existing binary in install-target order.
find_tool() {
  d=$1
  for _dir in "$fallback_bin" "$default_gobin"; do
    if [ -x "$_dir/$d" ]; then printf '%s\n' "$_dir/$d"; return 0; fi
  done
  return 1
}

# Skip downloads when the pinned tools are already in place (idempotent).
need_lefthook=1
_tool_path=$(find_tool lefthook 2>/dev/null || true)
if [ -n "$_tool_path" ] && "$_tool_path" version 2>/dev/null | grep -q "${LEFTHOOK_VERSION#v}"; then
  need_lefthook=0
fi
need_golangci=1
_tool_path=$(find_tool golangci-lint 2>/dev/null || true)
if [ -n "$_tool_path" ] && "$_tool_path" --version 2>/dev/null | grep -q "${GOLANGCI_LINT_VERSION#v}"; then
  need_golangci=0
fi

GOBIN="$default_gobin"
if [ "$need_lefthook" = 1 ] || [ "$need_golangci" = 1 ]; then
  mkdir -p "$GOBIN" 2>/dev/null || true
  if ! [ -w "$GOBIN" ]; then
    GOBIN="$fallback_bin"
    mkdir -p "$GOBIN"
    echo "install-hook-tools: $default_gobin is not writable; installing to $GOBIN"
  fi
fi
export GOBIN

if [ "$need_lefthook" = 0 ] && [ "$need_golangci" = 0 ]; then
  echo "install-hook-tools: pinned tools already present"
fi

os=$(uname -s)   # Darwin / Linux
arch=$(uname -m) # arm64 / x86_64 / aarch64

case "$os-$arch" in
  Darwin-arm64)
    lefthook_asset="lefthook_${LEFTHOOK_VERSION#v}_MacOS_arm64.gz"
    golangci_asset="golangci-lint-${GOLANGCI_LINT_VERSION#v}-darwin-arm64.tar.gz" ;;
  Darwin-x86_64)
    lefthook_asset="lefthook_${LEFTHOOK_VERSION#v}_MacOS_x86_64.gz"
    golangci_asset="golangci-lint-${GOLANGCI_LINT_VERSION#v}-darwin-amd64.tar.gz" ;;
  Linux-x86_64)
    lefthook_asset="lefthook_${LEFTHOOK_VERSION#v}_Linux_x86_64.gz"
    golangci_asset="golangci-lint-${GOLANGCI_LINT_VERSION#v}-linux-amd64.tar.gz" ;;
  Linux-aarch64|Linux-arm64)
    lefthook_asset="lefthook_${LEFTHOOK_VERSION#v}_Linux_aarch64.gz"
    golangci_asset="golangci-lint-${GOLANGCI_LINT_VERSION#v}-linux-arm64.tar.gz" ;;
  *)
    # No prebuilt mapping; the `go install` fallback below still works.
    lefthook_asset=""
    golangci_asset="" ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ "$os" = "Darwin" ]; then sha_cmd="shasum -a 256"; else sha_cmd="sha256sum"; fi

# fetch_github_asset <repo> <tag> <asset> <checksums-file> <out>
# Non-zero return => caller falls back to `go install`.
fetch_github_asset() {
  repo=$1 tag=$2 asset=$3 sums=$4 out=$5
  base="https://github.com/${repo}/releases/download/${tag}"
  curl -fsSL "${base}/${asset}" -o "$out" || return 1
  curl -fsSL "${base}/${sums}" -o "$tmp/checksums.txt" || return 1
  (cd "$tmp" && grep " ${asset}\$" checksums.txt | $sha_cmd -c -) || return 1
}

# go_install_sandbox_safe <package@version>
# Relocates GOPATH/GOCACHE to the session temp dir when the defaults are not
# writable, so `go install` works inside restricted sandboxes.
go_install_sandbox_safe() {
  modcache=$(go env GOMODCACHE 2>/dev/null || true)
  mkdir -p "$modcache" 2>/dev/null || true
  if ! [ -w "$modcache" ]; then
    # Relocate GOPATH as a whole, not just GOMODCACHE: the checksum database
    # cache (GOPATH/pkg/sumdb) is also written to during module downloads.
    export GOPATH="$fallback_root/gopath"
    export GOMODCACHE="$GOPATH/pkg/mod"
    mkdir -p "$GOMODCACHE"
    echo "install-hook-tools: module cache not writable; using $GOMODCACHE (GOPATH=$GOPATH)"
  fi
  gocache=$(go env GOCACHE 2>/dev/null || true)
  mkdir -p "$gocache" 2>/dev/null || true
  if ! [ -w "$gocache" ]; then
    export GOCACHE="$fallback_root/go-build"
    mkdir -p "$GOCACHE"
    echo "install-hook-tools: build cache not writable; using $GOCACHE"
  fi
  go install "$1"
}

restricted_env_hint="install-hook-tools: could not fetch the pinned tool in this restricted environment
  (module downloads are redirected to a host the sandbox does not allow).
  Fix: run \`make hooks\` once from an unrestricted terminal. The binaries install
  to ~/go/bin, which restricted shells can still read and run."

if [ "$need_lefthook" = 1 ]; then
  if [ -n "$lefthook_asset" ] \
    && fetch_github_asset evilmartians/lefthook "$LEFTHOOK_VERSION" "$lefthook_asset" lefthook_checksums.txt "$tmp/lefthook.gz"; then
    gunzip -f "$tmp/lefthook.gz"
    chmod +x "$tmp/lefthook"
    mv "$tmp/lefthook" "$GOBIN/lefthook"
  else
    echo "install-hook-tools: lefthook release download unavailable; using go install (slower, one-time)"
    if ! go_install_sandbox_safe "github.com/evilmartians/lefthook/v2@${LEFTHOOK_VERSION}"; then
      echo "$restricted_env_hint" >&2
      exit 1
    fi
  fi
fi

if [ "$need_golangci" = 1 ]; then
  if [ -n "$golangci_asset" ] \
    && fetch_github_asset golangci/golangci-lint "$GOLANGCI_LINT_VERSION" "$golangci_asset" "golangci-lint-${GOLANGCI_LINT_VERSION#v}-checksums.txt" "$tmp/golangci-lint.tar.gz"; then
    tar -xzf "$tmp/golangci-lint.tar.gz" -C "$tmp"
    golangci_bin=$(find "$tmp" -type f -name golangci-lint | sort | sed -n 1p)
    chmod +x "$golangci_bin"
    mv "$golangci_bin" "$GOBIN/golangci-lint"
  else
    echo "install-hook-tools: golangci-lint release download unavailable; using go install (slower, one-time)"
    if ! go_install_sandbox_safe "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}"; then
      echo "$restricted_env_hint" >&2
      exit 1
    fi
  fi
fi

lefthook_bin=$(find_tool lefthook)
golangci_bin=$(find_tool golangci-lint)

# Deliberately last and all-or-nothing: hooks only activate once the pinned
# toolchain is complete, so partial installs never leave fail-closed hooks.
"$lefthook_bin" install

echo "installed:"
"$lefthook_bin" version
"$golangci_bin" --version
command -v lefthook >/dev/null 2>&1 || echo "note: hook shims resolve tools via scripts/hook-env.sh"
