#!/usr/bin/env bash
# mutation_verify.sh — prove a hardening guard is load-bearing. Reverts the
# guard, runs the paired test, and asserts it now FAILS; then
# restores the file byte-identically. A guard the test can't detect is a guard
# with no regression protection.
#
# Convention: wrap the guard in marker comments in the source file:
#
#     // GUARD:foo >>>
#     if (n > maxAddressable) throw const FormatException('...');
#     // GUARD:foo <<<
#
# Usage:
#   mutation_verify.sh --file <src> --guard <name> --test '<command>'
#     e.g. --file lib/foo.dart --guard foo --test 'dart test test/foo_test.dart'
set -uo pipefail
file=""; guard=""; test_cmd=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --file)  file="$2";     shift 2 ;;
    --guard) guard="$2";    shift 2 ;;
    --test)  test_cmd="$2"; shift 2 ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done
[[ -n "$file" && -n "$guard" && -n "$test_cmd" ]] || {
  echo "usage: mutation_verify.sh --file F --guard NAME --test 'CMD'"; exit 2; }
[[ -f "$file" ]] || { echo "✗ no such file: $file"; exit 2; }
grep -q "GUARD:$guard >>>" "$file" || {
  echo "✗ no '// GUARD:$guard >>>' marker in $file — wrap the guard first."; exit 3; }

bak="$(mktemp)"; cp "$file" "$bak"
restore() { cp "$bak" "$file"; rm -f "$bak"; }
trap restore EXIT

# Comment out every line strictly between the guard markers.
awk -v g="$guard" '
  $0 ~ ("GUARD:" g " >>>") { print; inb=1; next }
  $0 ~ ("GUARD:" g " <<<") { inb=0; print; next }
  inb { print "// [mutation] " $0; next }
  { print }
' "$bak" > "$file"

echo "→ guard '$guard' reverted in $file; running test (expecting FAILURE)…"
if eval "$test_cmd" > /tmp/mv_out.txt 2>&1; then
  echo "✗ MUTATION NOT CAUGHT — the test still passed with the guard removed."
  echo "  The test does not exercise this guard; strengthen it."
  tail -3 /tmp/mv_out.txt | sed 's/^/    /'
  exit 1
else
  echo "✓ mutation caught — test failed with the guard removed (as intended)."
  grep -m1 -iE "RangeError|StateError|TypeError|StackOverflow|Expected|throws" \
    /tmp/mv_out.txt | sed 's/^/    /' || true
  echo "  (file restored byte-identically)"
  exit 0
fi
