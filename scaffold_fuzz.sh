#!/usr/bin/env bash
# scaffold_fuzz.sh — drop the fuzz harness into a target repo and stub a wiring
# file you fill in. Usage:
#
#   scaffold_fuzz.sh <repo-dir> <package-name> <import-path> <name>
#
#   repo-dir      : the Dart/Flutter package root (has pubspec.yaml)
#   package-name  : the `name:` from its pubspec.yaml
#   import-path   : the lib-relative path to the parser, e.g. src/foo_reader.dart
#   name          : short label for the harness, e.g. foo
#
# Produces <repo>/tool/fuzz_lib.dart (copied) and <repo>/tool/fuzz_<name>.dart
# (a stub with TODO markers). Edit the stub's seeds + entry, then:
#   cd <repo> && dart run tool/fuzz_<name>.dart
set -euo pipefail
kit="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="${1:?repo-dir}"; pkg="${2:?package-name}"; path="${3:?import-path}"; name="${4:?name}"
[[ -f "$repo/pubspec.yaml" ]] || { echo "✗ $repo has no pubspec.yaml"; exit 2; }
mkdir -p "$repo/tool"
cp "$kit/fuzz_lib.dart" "$repo/tool/fuzz_lib.dart"
out="$repo/tool/fuzz_${name}.dart"
if [[ -e "$out" ]]; then echo "✗ $out already exists — not overwriting"; exit 3; fi
cat > "$out" <<DART
// Throwaway fuzz harness for ${path}. Delete after hardening (or keep the
// findings as a *_test.dart regression). Run: dart run tool/fuzz_${name}.dart
import 'dart:typed_data'; // ignore: unused_import — for byte parsers
import 'fuzz_lib.dart';
// ignore: unused_import — used once you wire entry() below
import 'package:${pkg}/${path%.dart}.dart';

void main() {
  // 1) Valid seeds — reach the deep parse paths (goldens for byte formats).
  final seeds = <String>[
    // TODO: paste valid inputs here
  ];

  // 2) Wire the parse entry point.
  void entry(String input) {
    // TODO: call your parser, e.g. parseFoo(input);
    throw UnimplementedError('wire the entry point');
  }

  // 3) Allow-list the clean-reject exceptions (default = FormatException only).
  //    Add your own reject types: (e) => e is FormatException || e is FooError
  bool isClean(Object e) => e is FormatException;

  final report = fuzz<String>(
    seeds: seeds,
    entry: entry,
    mutate: mutateString, // or mutateBytes for Uint8List parsers
    isClean: isClean,
    // Structural cases random mutation misses (deep nesting, size bombs):
    stressors: [
      // '(' * 20000, '9' * 100000, ...
    ],
  );
  final code = report.report();
  // Non-zero exit = escapes (1) or slow/bomb (2); 0 = clean & fast.
  if (code != 0) print('\\n→ investigate the escape / slow report above.');
}
DART
echo "✓ wrote $out"
echo "  next: edit seeds + entry, then  (cd $repo && dart run tool/fuzz_${name}.dart)"
