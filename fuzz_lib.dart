// fuzz_lib.dart — reusable reader-robustness fuzzing harness.
//
// Drop this into a target repo's tool/ dir (scaffold_fuzz.sh does it for you),
// write a ~15-line harness that wires up your parse entry point, and run it
// with `dart run tool/<harness>.dart`.
//
// The contract it checks: a reader must never crash
// or hang on malformed input — it parses leniently or rejects with a
// *clean* exception (FormatException, or your own *FormatException type). A
// leaked RangeError / StateError / TypeError, an OOM, or a slow "parse" is a bug.
//
// It also flags the SLOW-PARSE TELL: tens of ms per iteration on small
// inputs means a size-driven allocation/loop bomb, not thorough coverage.

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

// ---------------------------------------------------------------------------
// Mutation operators
// ---------------------------------------------------------------------------

const _stringPool = ' \n\t0123456789.,:;-+*/()[]{}<>=!"\\abcXYZ';

/// One mutation of a String seed: delete / replace / insert / uppercase.
String mutateString(String seed, Random rng, {int maxOps = 8}) {
  final b = seed.split('');
  final ops = 1 + rng.nextInt(maxOps);
  for (var o = 0; o < ops && b.isNotEmpty; o++) {
    final at = rng.nextInt(b.length);
    switch (rng.nextInt(4)) {
      case 0:
        b.removeAt(at);
      case 1:
        b[at] = _stringPool[rng.nextInt(_stringPool.length)];
      case 2:
        b.insert(at, _stringPool[rng.nextInt(_stringPool.length)]);
      default:
        b[at] = b[at].toUpperCase();
    }
  }
  return b.join();
}

/// One mutation of a byte seed: replace / bit-flip / insert / delete / truncate.
/// Seed from a VALID encoding so mutations keep enough structure (magic bytes,
/// signatures) to reach the deep parse paths where the bugs live.
Uint8List mutateBytes(Uint8List seed, Random rng, {int maxOps = 8}) {
  final b = List<int>.of(seed);
  final ops = 1 + rng.nextInt(maxOps);
  for (var o = 0; o < ops && b.isNotEmpty; o++) {
    final at = rng.nextInt(b.length);
    switch (rng.nextInt(5)) {
      case 0:
        b[at] = rng.nextInt(256);
      case 1:
        b[at] ^= 1 << rng.nextInt(8);
      case 2:
        b.insert(at, rng.nextInt(256));
      case 3:
        b.removeAt(at);
      default:
        b.removeRange(at, b.length); // truncate
    }
  }
  return Uint8List.fromList(b);
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

class FuzzReport {
  final int runs;
  final int elapsedMs;
  final int maxSingleMs;
  final Map<String, int> escapes;
  final Map<String, String> examples;
  FuzzReport(
      this.runs, this.elapsedMs, this.maxSingleMs, this.escapes, this.examples);

  bool get clean => escapes.isEmpty;

  /// The slow-parse tell: a size-driven bomb makes the fuzzer crawl.
  bool get slow =>
      (runs > 0 && elapsedMs / runs > 5) || maxSingleMs > 200;

  /// Prints the report and returns a process exit code (0 = clean & fast).
  int report() {
    final avg = runs == 0 ? 0.0 : elapsedMs / runs;
    stdout.writeln('runs=$runs elapsed=${elapsedMs}ms '
        'maxSingle=${maxSingleMs}ms avg=${avg.toStringAsFixed(3)}ms/iter');
    if (slow) {
      stdout.writeln('⚠ SLOW: >5ms/iter or a >200ms single parse — likely a '
          'size-driven allocation/loop bomb. Bisect, then craft a minimal '
          'repro to root-cause it.');
    }
    if (clean) {
      stdout.writeln('CLEAN: only allow-listed clean-reject exceptions'
          '${slow ? ' (but see SLOW above)' : ''}.');
      return slow ? 2 : 0;
    }
    stdout.writeln('ESCAPES (contract violations): $escapes');
    examples.forEach((k, v) =>
        stdout.writeln('  $k <= ${v.replaceAll('\n', '\\n')}'));
    return 1;
  }
}

/// Fuzz [entry] over mutations of [seeds].
///
/// [isClean] returns true for exceptions that are the documented clean-reject
/// contract — FormatException, and any of YOUR OWN reject types. Everything
/// else is recorded as an escape. Default: FormatException only.
///
/// [stressors] are extra one-shot inputs appended after the random pass — use
/// them for the structural cases random mutation rarely hits: deep nesting
/// (`'(' * 20000`), huge repeats, u16/u32-max declared counts.
FuzzReport fuzz<T>({
  required List<T> seeds,
  required void Function(T input) entry,
  required T Function(T seed, Random rng) mutate,
  bool Function(Object e)? isClean,
  int iterations = 200000,
  int budgetMs = 60000,
  int seed = 20260718,
  List<T> stressors = const [],
}) {
  final clean = isClean ?? (e) => e is FormatException;
  final rng = Random(seed);
  final escapes = <String, int>{};
  final examples = <String, String>{};
  var runs = 0, maxMs = 0;
  final sw = Stopwatch()..start();

  void run(T input) {
    runs++;
    final t = Stopwatch()..start();
    try {
      entry(input);
    } catch (e) {
      if (!clean(e)) {
        final k = e.runtimeType.toString();
        escapes[k] = (escapes[k] ?? 0) + 1;
        examples.putIfAbsent(k, () {
          final s = input.toString();
          return s.length > 80 ? '${s.substring(0, 80)}…' : s;
        });
      }
    }
    final ms = t.elapsedMilliseconds;
    if (ms > maxMs) maxMs = ms;
  }

  for (var i = 0; i < iterations; i++) {
    run(mutate(seeds[rng.nextInt(seeds.length)], rng));
    if (sw.elapsedMilliseconds > budgetMs) {
      stdout.writeln('(time budget hit at i=$i / $iterations)');
      break;
    }
  }
  for (final s in stressors) {
    run(s);
  }
  return FuzzReport(runs, sw.elapsedMilliseconds, maxMs, escapes, examples);
}
