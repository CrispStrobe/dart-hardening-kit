# dart-hardening-kit

Scaffolding for **reader-robustness fuzzing** of Dart parsers — code that reads
untrusted input (binary formats, text protocols, JSON from the network). It
automates the mechanical parts of the loop (discovery, harness plumbing,
fuzzability probing, crash minimization, mutation-verification) so the work
that remains is triage and the fix.

The runner surfaces two failure classes:

- **Escapes** — a `RangeError` / `StateError` / `TypeError` leaking where a
  clean rejection was expected, and reduces each to a **minimal reproducer**.
- **Slow parses** — tens of milliseconds per iteration on small inputs, the
  signature of a size-driven allocation or loop bomb (a denial-of-service).

## The contract it checks

A parser reading untrusted input must never crash or hang on malformed data. It
either parses leniently or rejects with a documented exception (`FormatException`,
or the parser's own reject type). A leaked `RangeError` / `StateError` /
`TypeError`, an out-of-memory, an infinite loop, or a multi-second parse is a
defect.

## Workflow

| Step | Tool |
|---|---|
| Enumerate a tree's parse entry points | `discover.sh` |
| Check whether a file fuzzes standalone (or is FFI-blocked) | `probe_fuzzable.sh` |
| Generate a harness | `scaffold_fuzz.sh` + `fuzz_lib.dart` |
| Run, collect escapes (minimized) + slow-parse signal | `fuzz_lib.dart` (exit code) |
| Prove a hardening guard is load-bearing | `mutation_verify.sh` |

Root-causing the escape and writing the fix are manual — the kit exists to make
those the only manual steps.

## Quick start

```bash
kit=/path/to/dart-hardening-kit

# Enumerate parse entry points under a tree.
"$kit/discover.sh" ~/projects | less

# Check whether a candidate compiles under bare `dart run`.
"$kit/probe_fuzzable.sh" ~/projects/my_package my_package src/foo_parser.dart
#   FUZZABLE    -> scaffold a harness
#   FFI-BLOCKED -> extract the pure functions into a standalone copy first

# Scaffold and wire the harness (fill in: seeds, entry call, clean-reject list).
"$kit/scaffold_fuzz.sh" ~/projects/my_package my_package src/foo_parser.dart foo
cd ~/projects/my_package && dart run tool/fuzz_foo.dart
#   CLEAN (exit 0) | ESCAPES (exit 1) | SLOW/bomb (exit 2)

# After fixing, wrap the guard in markers and verify the test catches it:
"$kit/mutation_verify.sh" \
  --file lib/src/foo_parser.dart --guard depth \
  --test 'dart test test/foo_parser_test.dart'
```

## Files

- **`fuzz_lib.dart`** — the harness. `mutateString` / `mutateBytes` mutation
  operators and a `fuzz(...)` runner that records escapes, **minimizes each to a
  small reproducer** via delta-debugging, and flags the slow-parse signal. Exit
  code: `0` clean and fast, `1` escapes, `2` clean but slow.
- **`scaffold_fuzz.sh`** — copies `fuzz_lib.dart` into `<repo>/tool/` and writes
  a `fuzz_<name>.dart` stub with three fields to complete: seeds, the entry
  call, and the clean-reject allow-list.
- **`probe_fuzzable.sh`** — compiles a one-line probe inside the package to
  detect the FFI-transformer failure that blocks bare `dart run` (a pure-Dart
  parser whose import chain reaches a `NativeCallable`).
- **`mutation_verify.sh`** — reverts a marker-wrapped guard, asserts the paired
  test now fails, and restores the file byte-identically.
- **`discover.sh`** — greps a tree for parse entry points (byte readers,
  `parseXxx(String)`, `fromJson`) and flags packages using `dart:ffi`.

## Seeds

Mutation-based fuzzing depends on good seeds. Start from valid encodings so
mutations retain enough structure (magic bytes, signatures, a valid JSON
envelope) to reach the deep parse paths where defects occur. Random bytes
mostly bounce off the format's magic check. For binary formats, seed from real
sample files; for JSON, from a valid document.

## Guard-marker convention

Wrap each hardening guard so `mutation_verify.sh` can revert it mechanically:

```dart
// GUARD:maxdepth >>>
if (depth > _maxDepth) throw const FormatException('nesting too deep');
// GUARD:maxdepth <<<
```

`mutation_verify.sh --guard maxdepth` comments out the block, runs the test
expecting failure (confirming the test exercises the guard), and restores the
file. A guard the test cannot detect has no regression protection.

## Prior art and design choices

Coverage-guided fuzzers — **libFuzzer**, **AFL++**, **Honggfuzz**, and the
**OSS-Fuzz** infrastructure built on them — are the state of the art for
C/C++/Rust. They instrument the target, evolve a corpus toward new coverage,
carry input dictionaries, and minimize crashes. Dart has no comparable
in-process coverage feedback at fuzzing speed, so this kit uses **blind
mutation from seeds**: weaker at reaching deep code, but zero-setup and fast to
apply across many packages.

Two ideas are borrowed directly:

- **Crash minimization** (libFuzzer `-minimize_crash`, AFL `tmin`): each escape
  is reduced by delta-debugging to a minimal input that still reproduces the
  same exception type — the single most time-consuming step to do by hand.
- **Guard-targeted mutation testing**: `mutation_verify.sh` is a narrow form of
  what **`package:mutation_test`** does across a whole file — it mutates exactly
  one hardening guard and checks the test catches it.

For property-based testing with generators and shrinking, **`package:glados`**
is the established Dart tool; it targets invariants over generated values,
whereas this kit targets the "never crash on malformed input" contract over
real-world seeds.

## Limitations and roadmap

- **No coverage feedback.** Mutation is blind; it will not synthesize an input
  that satisfies a checksum or a multi-field precondition the way a
  coverage-guided fuzzer can. A VM-coverage-driven corpus is the largest
  possible improvement.
- **No structure-aware mutation.** Dumb byte-flipping bounces off magic numbers
  and checksums. An input dictionary (libFuzzer `-dict` style) of format tokens
  would reach deeper; it is a natural extension of `mutateBytes`.
- **Triage is manual.** The allow-list distinguishes a deliberate reject type
  from a real leak; the kit does not decide whether a finding clears a given
  threat model, nor does it write the fix.
- **`probe_fuzzable.sh` is slow on large Flutter apps** because it runs a real
  `dart pub get` and compile per file. Batch runs should parallelize or cache.

## Requirements

- Dart SDK 3.x
- `bash` for the shell scripts

## License

MIT — see [LICENSE](LICENSE).
