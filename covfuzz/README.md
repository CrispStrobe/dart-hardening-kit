# covfuzz

Coverage-guided corpus-evolution fuzzer for Dart parsers. Where the top-level
kit's `fuzz_lib.dart` mutates blindly, covfuzz reads its own coverage from the
VM service after each input and keeps any input that reaches new code as a
corpus seed — the libFuzzer/AFL corpus-evolution loop, using the only coverage
signal Dart exposes.

## Why

Blind mutation cannot get past a magic check or a multi-field precondition: it
would have to satisfy every byte at once. Coverage guidance earns each matched
condition as new coverage and builds on it.

Demo (`example/`, a parser with a bug behind a 4-byte `FUZZ` magic):

```
BLIND: 500k mutations, RangeErrors found = 0
COVERAGE-GUIDED:
  exec=946    coverage=8   corpus=2          (matched 'F')
  exec=1252   coverage=12  corpus=3          (matched 'FU')
  exec=6770   coverage=16  corpus=4          (matched 'FUZ')
  exec=13483  coverage=20  corpus=5  [ESCAPE RangeError]   (matched 'FUZZ' → bug)
  RangeError — minimal repro (len=5): [70, 85, 90, 90, 8]   ("FUZZ" + length 8)
```

Blind never produces the four magic bytes plus a bad length in one mutation
(~2⁻³²); covfuzz climbs the four conditions in ~13k executions and minimizes the
crash to its exact 5-byte trigger.

## Usage

covfuzz reads coverage from the VM service, so the harness **must** run with it
enabled:

```bash
dart run --enable-vm-service=0 --no-pause-isolates-on-exit tool/covfuzz_foo.dart
```

A harness:

```dart
import 'dart:typed_data';
import 'package:covfuzz/covfuzz.dart';
import 'package:my_pkg/src/foo_parser.dart';

Future<void> main() async {
  final r = await covFuzz<Uint8List>(
    seeds: [/* valid sample(s) */],
    entry: (b) => parseFoo(b),
    mutate: mutateBytes,             // or mutateString
    targetLib: 'package:my_pkg/src/foo_parser.dart', // library to score coverage on
    isClean: (e) => e is FormatException,            // your clean-reject types
    iterations: 40000,
    budgetMs: 120000,
    corpusDir: '.corpus/foo',        // optional: persist the evolved corpus
    crashDir: '.crashes/foo',        // optional: save minimized crashes
    log: true,                       // print the coverage climb
  );
  r.report();                        // prints; returns 0 clean, 1 escapes
}
```

`corpusDir` persists new-coverage inputs across runs (OSS-Fuzz style): a later
run reloads them as seeds and continues from the coverage already reached.

## Throughput and limits

- The VM-service coverage query runs after **every** input (correct per-input
  attribution) and costs a few milliseconds, so throughput is ~100–1000
  execs/sec depending on target size — orders of magnitude below a
  natively-instrumented fuzzer, but it evolves a corpus blind mutation cannot.
  Run it for minutes-to-hours; persist the corpus.
- The target runs **in-process**, so a hard hang (a synchronous infinite loop)
  freezes the fuzzer — Dart cannot interrupt it. Shake hangs out first with the
  blind `fuzz_lib.dart` (it reports the slow-parse signal), then run covfuzz to
  reach depth.
- Coverage is process-global and cumulative: run each covfuzz session in its own
  process so a prior run doesn't pollute the baseline.
- `mutateBytes` is biased toward in-place edits (replace / bit-flip) so byte
  positions stay stable enough for coverage to match positional magic bytes.

## Requirements

- Dart SDK 3.x
- `package:vm_service` (declared in `pubspec.yaml`)
