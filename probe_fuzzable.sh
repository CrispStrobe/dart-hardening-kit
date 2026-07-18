#!/usr/bin/env bash
# probe_fuzzable.sh — can this lib file be fuzzed under bare `dart run`, or does
# its import chain crash the FFI transformer (needing the extract-pure-logic
# workaround)?  Usage:
#
#   probe_fuzzable.sh <repo-dir> <package-name> <import-path>
#     e.g. probe_fuzzable.sh ~/projects/my_package my_package src/foo_parser.dart
#
# Prints one of: FUZZABLE | FFI-BLOCKED | OTHER-ERROR (with the message).
set -uo pipefail
repo="${1:?repo-dir}"; pkg="${2:?package-name}"; path="${3:?import-path}"
[[ -f "$repo/pubspec.yaml" ]] || { echo "✗ $repo has no pubspec.yaml"; exit 2; }
# The probe must live INSIDE the package so `dart run` resolves package: imports.
mkdir -p "$repo/tool"
probe="$repo/tool/.probe_fuzzable_$$.dart"
printf "import 'package:%s/%s.dart';\nvoid main() { print('FUZZABLE_OK_MARKER'); }\n" \
  "$pkg" "${path%.dart}" > "$probe"
# resolve deps quietly (best-effort; ignore failures — the run below is the test)
( cd "$repo" && dart pub get >/dev/null 2>&1 || true )
out="$(cd "$repo" && dart run "tool/$(basename "$probe")" 2>&1 || true)"
rm -f "$probe"
# Match loosely: Flutter's "Running build hooks..." prints without a newline, so
# the marker can be appended to another line rather than sitting on its own.
if grep -q "FUZZABLE_OK_MARKER" <<<"$out"; then
  echo "FUZZABLE   $path"
elif grep -qE "is not a subtype of type 'FunctionType'|_FfiUseSiteTransformer|dart:ffi" <<<"$out"; then
  echo "FFI-BLOCKED $path — extract the pure logic into a standalone copy first"
else
  echo "OTHER-ERROR $path"
  sed -n '1,3p' <<<"$out" | sed 's/^/    /'
fi
