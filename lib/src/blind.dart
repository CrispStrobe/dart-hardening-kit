// Blind mutation fuzzing — no coverage feedback, zero setup, ~1M execs/sec.
// Fast first pass: it shakes out the crashes and the slow-parse (bomb) signal
// before you reach for the coverage-guided `covFuzz`.

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'mutators.dart';

class FuzzReport {
  final int runs;
  final int elapsedMs;
  final int maxSingleMs;
  final Map<String, int> escapes;

  /// Per escape type, a minimized reproducer (`toString`) and its size.
  final Map<String, String> minimalRepro;
  final Map<String, int> minimalSize;

  FuzzReport(this.runs, this.elapsedMs, this.maxSingleMs, this.escapes,
      this.minimalRepro, this.minimalSize);

  bool get clean => escapes.isEmpty;

  /// The slow-parse tell: a size-driven allocation/loop bomb makes the fuzzer
  /// crawl (tens of ms per iteration on small inputs).
  bool get slow => (runs > 0 && elapsedMs / runs > 5) || maxSingleMs > 200;

  /// Prints the report; returns a process exit code (0 clean & fast).
  int report() {
    final avg = runs == 0 ? 0.0 : elapsedMs / runs;
    stdout.writeln('runs=$runs elapsed=${elapsedMs}ms '
        'maxSingle=${maxSingleMs}ms avg=${avg.toStringAsFixed(3)}ms/iter');
    if (slow) {
      stdout.writeln('SLOW: >5ms/iter or a >200ms single parse — likely a '
          'size-driven allocation/loop bomb. Bisect, then craft a minimal '
          'repro to root-cause it.');
    }
    if (clean) {
      stdout.writeln('CLEAN: only allow-listed clean-reject exceptions'
          '${slow ? ' (but see SLOW above)' : ''}.');
      return slow ? 2 : 0;
    }
    stdout.writeln('ESCAPES (contract violations): $escapes');
    for (final k in minimalRepro.keys) {
      stdout.writeln('  $k — minimal repro (len=${minimalSize[k]}): '
          '${minimalRepro[k]!.replaceAll('\n', '\\n')}');
    }
    return 1;
  }
}

/// Blind-fuzz [entry] over mutations of [seeds].
///
/// [isClean] returns true for exceptions that are the documented clean-reject
/// contract — `FormatException`, and any of your own reject types. Everything
/// else is recorded as an escape and minimized. Default: `FormatException`.
///
/// [stressors] are extra one-shot inputs appended after the random pass — for
/// the structural cases random mutation rarely hits (deep nesting, huge
/// repeats, u16/u32-max declared counts).
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
  final firstFail = <String, T>{};
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
        firstFail.putIfAbsent(k, () => input);
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

  final minimalRepro = <String, String>{};
  final minimalSize = <String, int>{};
  firstFail.forEach((type, input) {
    final m = minimize(input, type, entry, clean);
    final s = m.toString();
    minimalRepro[type] = s.length > 200 ? '${s.substring(0, 200)}…' : s;
    minimalSize[type] =
        m is String ? m.length : (m is Uint8List ? m.length : -1);
  });

  return FuzzReport(
      runs, sw.elapsedMilliseconds, maxMs, escapes, minimalRepro, minimalSize);
}
