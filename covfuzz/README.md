# covfuzz

Reader-robustness fuzzing for Dart parsers — code that reads untrusted input
(binary formats, text protocols, JSON from the network). One library, two tiers,
plus command-line tools for the surrounding workflow.

The contract it checks: a parser must never crash or hang on malformed input. It
either parses leniently or rejects with a documented exception
(`FormatException`, or its own reject type). A leaked `RangeError` /
`StateError` / `TypeError`, an out-of-memory, an infinite loop, or a
multi-second parse is a defect. Any thrown exception outside your allow-list is
recorded and reduced to a minimal reproducer.

## Install

```yaml
dev_dependencies:
  covfuzz: ^0.1.0
```

## Library

### Blind fuzzing — `fuzz`

Zero setup, ~1M execs/sec. The fast first pass: it shakes out crashes and the
slow-parse (bomb) signal, and minimizes each escape.

```dart
import 'dart:typed_data';
import 'package:covfuzz/covfuzz.dart';
import 'package:my_pkg/src/foo_parser.dart';

void main() {
  final report = fuzz<Uint8List>(
    seeds: [validSample],               // valid input(s) — mutations start here
    entry: (b) => parseFoo(b),
    mutate: mutateBytes,                // or mutateString
    isClean: (e) => e is FormatException, // your clean-reject types
    stressors: [Uint8List(0), hugeInput], // structural cases mutation misses
  );
  report.report(); // prints; returns 0 clean & fast, 1 escapes, 2 clean-but-slow
}
```

### Coverage-guided fuzzing — `covFuzz`

For paths behind a magic check or a multi-field precondition that blind mutation
can't reach. It reads the target library's coverage from the VM service after
each input and keeps any input that reaches new code as a corpus seed, so the
corpus evolves toward deep code.

**Must** run with the VM service enabled:

```bash
dart run --enable-vm-service=0 --no-pause-isolates-on-exit tool/covfuzz_foo.dart
```

```dart
final r = await covFuzz<Uint8List>(
  seeds: [validSample],
  entry: (b) => parseFoo(b),
  mutate: mutateBytes,
  targetLib: 'package:my_pkg/src/foo_parser.dart', // library to score coverage on
  isClean: (e) => e is FormatException,
  corpusDir: '.corpus/foo',  // optional: persist the evolved corpus across runs
  crashDir: '.crashes/foo',  // optional: save minimized crashes
  log: true,                 // print the coverage climb
);
r.report();
```

On the bundled demo (`example/`, a bug behind a 4-byte `FUZZ` magic), blind
mutation finds nothing in 500k tries while covFuzz climbs the four conditions
(coverage 8→12→16→20) and reports the minimized 5-byte trigger `[70,85,90,90,8]`.

## Command-line tools

`dart pub global activate covfuzz` (or `dart run covfuzz:<tool>`):

- **`covfuzz_discover [root]`** — list a tree's packages and their parse entry
  points (byte readers, `parseXxx(String)`, `fromJson`); flags `dart:ffi` users.
- **`covfuzz_probe <repo> <pkg> <import-path>`** — does the file fuzz under bare
  `dart run`, or is it FFI-blocked (extract the pure logic first)?
- **`covfuzz_scaffold <pkg> <import-path> <name> [--bytes]`** — write a harness
  stub in `tool/`.
- **`covfuzz_mutverify --file F --guard NAME --test 'CMD'`** — prove a hardening
  guard is load-bearing: revert a marker-wrapped guard, run the test expecting
  failure, restore the file byte-identically. Wrap guards as:
  ```dart
  // GUARD:maxdepth >>>
  if (depth > _maxDepth) throw const FormatException('nesting too deep');
  // GUARD:maxdepth <<<
  ```

## Seeds

Start from valid encodings so mutations keep enough structure (magic bytes,
signatures, a valid JSON envelope) to reach deep parse paths. Random bytes
mostly bounce off the format's magic check. Seed binary formats from real sample
files; JSON from a valid document.

## Prior art and limits

Coverage-guided fuzzers — libFuzzer, AFL++, OSS-Fuzz — are the state of the art
for C/C++/Rust, with native per-execution coverage hitmaps. Dart has no such
in-process signal, so covFuzz reads coverage from the VM service (one query per
input, ~100–1000 execs/sec — orders below a native fuzzer, but it evolves a
corpus blind mutation cannot). Crash minimization borrows libFuzzer's
`-minimize_crash`; `covfuzz_mutverify` is a guard-targeted form of what
`package:mutation_test` does across a file; for property testing with shrinking,
`package:glados` is the established Dart tool.

- The target runs in-process, so a hard hang freezes covFuzz — shake hangs out
  with blind `fuzz` first.
- Coverage is process-global and cumulative — run each covFuzz session in its
  own process.
- No structure-aware / dictionary mutation yet; `mutateBytes` is biased toward
  in-place edits so positions stay stable enough to match magic bytes.

## Requirements

Dart SDK 3.x. Native platforms only (`dart:io` + VM service).

## License

MIT — see [LICENSE](LICENSE).
