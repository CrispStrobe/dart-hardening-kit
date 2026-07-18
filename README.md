# dart-hardening-kit

Lightweight scaffolding for **reader-robustness fuzzing** of Dart parsers — the
loop that finds crashes, hangs, and decode-bombs in code that reads untrusted
input (binary formats, text protocols, JSON from the network).

It mechanizes the boilerplate — discovery, fuzzer plumbing, fuzzability probing,
mutation-verification — and leaves you the judgment: *is this escape a real bug,
what's the root cause, and what's the right fix.*

> A **fuzzing farm + triage harness**, not an auto-fixer. It surfaces contract
> violations (a `RangeError`/`TypeError`/`StateError` leaking where a clean
> rejection was expected) and slow parses (size-driven allocation bombs). It does
> not decide whether a finding is a real bug or write the fix — that's the
> reasoning step it exists to feed.

## The contract it checks

A parser reading untrusted input must **never crash or hang** on malformed data —
it either parses leniently or rejects with a *clean, documented* exception
(`FormatException`, or the parser's own reject type). A leaked `RangeError` /
`StateError` / `TypeError`, an out-of-memory, an infinite loop, or a
multi-second "parse" is a bug.

## The loop, and which tool covers each step

| Step | Tool | Judgment left to you |
|---|---|---|
| Find packages + parse entry points | `discover.sh` | which are worth fuzzing |
| Can it fuzz standalone? | `probe_fuzzable.sh` | if FFI-blocked, extract the pure logic first |
| Write the fuzzer | `scaffold_fuzz.sh` + `fuzz_lib.dart` | seeds + the clean-reject allow-list |
| Run + collect escapes / slow-parse | `fuzz_lib.dart` (exit code) | *is an escape a real bug?* |
| Root-cause + fix | — | the actual engineering |
| Prove the guard is load-bearing | `mutation_verify.sh` | wrap the guard in markers |

## Quick start

```bash
kit=/path/to/dart-hardening-kit

# 1. What's out there?
"$kit/discover.sh" ~/projects | less

# 2. Pick a candidate; can it fuzz under bare `dart run`?
"$kit/probe_fuzzable.sh" ~/projects/my_package my_package src/foo_parser.dart
#   FUZZABLE    -> scaffold a harness
#   FFI-BLOCKED -> extract the pure functions into a standalone copy first

# 3. Scaffold + wire the harness (edit the TODOs: seeds + entry + allow-list).
"$kit/scaffold_fuzz.sh" ~/projects/my_package my_package src/foo_parser.dart foo
cd ~/projects/my_package && dart run tool/fuzz_foo.dart
#   CLEAN (exit 0) | ESCAPES (exit 1) | SLOW/bomb (exit 2)

# 4. Fix the bug, wrap the guard in markers, add a regression test, then:
"$kit/mutation_verify.sh" \
  --file lib/src/foo_parser.dart --guard depth \
  --test 'dart test test/foo_parser_test.dart'
```

## Files

- **`fuzz_lib.dart`** — the reusable harness. `mutateString` / `mutateBytes`
  operators + a `fuzz(...)` runner that records escapes, tracks the slowest
  single parse, and flags the **slow-parse tell** (tens of ms per iteration on
  small inputs = a size-driven allocation/loop bomb, not thorough coverage).
  Exit code: `0` clean & fast, `1` escapes, `2` clean but slow (a likely bomb).
- **`scaffold_fuzz.sh`** — copies `fuzz_lib.dart` into `<repo>/tool/` and writes
  a `fuzz_<name>.dart` stub with the three things you fill in: seeds, the entry
  call, and the clean-reject allow-list.
- **`probe_fuzzable.sh`** — compiles a one-line probe *inside* the package to
  detect the FFI-transformer crash that blocks bare `dart run` (a pure-Dart
  parser in a Flutter app whose import chain pulls a `NativeCallable`).
- **`mutation_verify.sh`** — reverts a marker-wrapped guard, asserts the paired
  test now fails, and restores the file byte-identically.
- **`discover.sh`** — greps every package under a root for parse entry points
  (byte readers, `parseXxx(String)`, `fromJson`) and flags `dart:ffi` users.

## Seeds matter

Mutation-based blackbox fuzzing needs **good seeds**: start from *valid*
encodings so mutations keep enough structure (magic bytes, signatures, a valid
JSON envelope) to reach the deep parse paths where the bugs live. Feeding pure
random bytes mostly bounces off the format's magic check and never exercises the
vulnerable code. For binary formats, seed from real sample files (a golden
fixture); for JSON, from a valid document.

## The guard-marker convention (for `mutation_verify.sh`)

Wrap each hardening guard so it can be mechanically reverted:

```dart
// GUARD:maxdepth >>>
if (depth > _maxDepth) throw const FormatException('nesting too deep');
// GUARD:maxdepth <<<
```

`mutation_verify.sh --file … --guard maxdepth --test '…'` comments out the block,
runs the test expecting it to fail (proving the test exercises the guard), then
restores the file byte-identically.

## What it can't do (be honest)

- **No coverage-guided fuzzing.** Dart has no libFuzzer/AFL equivalent, so this
  is mutation-based blackbox from good seeds.
- **It won't triage for you.** It can't tell a *deliberate* reject type (your own
  `FooException`) from a real leak — you declare that in the allow-list. And it
  won't decide whether a finding clears your threat-model bar.
- **It won't root-cause or write the fix.** That's the reasoning step; the kit
  exists to put every escape in front of a reasoner fast.

## Requirements

- Dart SDK 3.x (`dart run`, `dart test`, `dart analyze`).
- `bash` for the shell scripts.

## License

MIT — see [LICENSE](LICENSE).
