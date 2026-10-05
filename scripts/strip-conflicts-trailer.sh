#!/bin/sh
# Commit-msg hook: git appends the "# Conflicts:" trailer (header plus the
# "#\t<path>" lines) at end-of-message when `git cherry-pick --continue`
# resolves conflicts. It is not wanted in history, so it is trimmed here.
f="$1"
[ -f "$f" ] || exit 0
if ! grep -q '^# Conflicts:$' "$f"; then
  exit 0
fi
awk '/^# Conflicts:$/ { exit } { print }' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
