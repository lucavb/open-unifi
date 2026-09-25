#!/usr/bin/env bash
# Full CI-parity gate on every push: `make check` | `make build` | `make lint`
# in parallel. Invoked as a lefthook *script* job, on purpose — lefthook v2
# silently skips pre-push `run:` jobs whenever `git diff HEAD @{push}` is
# empty (branch in sync) or unresolvable (first push of a new branch, the
# agent PR flow); script jobs are exempt from that implicit {push_files} gate
# (upstream: evilmartians/lefthook#554). Bypass, as for any lefthook hook:
# LEFTHOOK=0 git push ...
echo "pre-push: CI-parity gate: make check | make build | make lint"
make check & _c=$!
make build & _b=$!
make lint & _l=$!
_status=0
wait "$_c" || _status=1
wait "$_b" || _status=1
wait "$_l" || _status=1
if [ "$_status" != 0 ]; then
  echo "pre-push: gate failed - fix the errors above, then push again (bypass: LEFTHOOK=0)" >&2
  exit 1
fi
