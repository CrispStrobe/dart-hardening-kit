#!/usr/bin/env bash
# discover.sh — enumerate Dart packages under a root and list their
# untrusted-input parse entry points (the fuzzing candidates). Fast, grep-only;
# use probe_fuzzable.sh to check whether a specific hit compiles standalone.
#
# Usage: discover.sh [root]   (default: ~/code)
set -uo pipefail
root="${1:-$HOME/code}"

for d in "$root"/*/; do
  d="${d%/}"
  [[ -f "$d/pubspec.yaml" ]] || continue
  # Entry-point signatures:
  #  - top-level/static fn taking Uint8List / List<int>  (binary readers)
  #  - parseXxx(String ...)                               (text parsers)
  #  - factory Xxx.fromJson                               (untrusted JSON)
  hits=$(grep -rnE \
    '(\b[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\((Uint8List|List<int>)[[:space:]]+)|(parse[A-Za-z0-9_]*[[:space:]]*\([[:space:]]*String[[:space:]])|(factory[[:space:]]+[A-Za-z0-9_]+\.fromJson)' \
    "$d/lib" --include="*.dart" 2>/dev/null \
    | grep -viE '(^|[^:])//|_test\.dart|\.g\.dart|\.freezed\.dart' | head -40)
  [[ -z "$hits" ]] || {
    name=$(awk '/^name:/{print $2; exit}' "$d/pubspec.yaml")
    ffi=$(grep -rlE "dart:ffi|NativeCallable" "$d/lib" --include="*.dart" 2>/dev/null | head -1)
    echo "### ${d##*/}   package=${name}${ffi:+   ⚠ package uses dart:ffi (probe_fuzzable.sh before you fuzz)}"
    sed -E "s|^$d/lib/|  |" <<<"$hits"
    echo
  }
done
