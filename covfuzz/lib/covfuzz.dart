// covfuzz — coverage-guided corpus-evolution fuzzer for Dart parsers.
//
// Blind mutation (fuzz_lib.dart) bounces off magic checks and multi-field
// preconditions. This version reads its own coverage from the VM service after
// each input; an input that raises the target library's cumulative coverage is
// kept as a new corpus seed, so the corpus evolves toward inputs that reach
// deep code — the libFuzzer/AFL corpus-evolution loop, using the only coverage
// signal Dart exposes (the VM service), so it is slower but reaches further.
//
// MUST be run with the VM service enabled:
//   dart run --enable-vm-service=0 --no-pause-isolates-on-exit tool/covfuzz_*.dart
//
// The target runs in-process, so a *hard hang* in the target freezes the
// fuzzer (Dart can't interrupt a synchronous loop). Shake hangs out with the
// blind fuzzer first (it reports the slow-parse signal), then run covfuzz to
// reach depth.

import 'dart:convert';
import 'dart:developer' as dev;
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:vm_service/vm_service.dart';
import 'package:vm_service/vm_service_io.dart';

// ---------------------------------------------------------------------------
// Mutators + minimizer (self-contained; mirror fuzz_lib.dart)
// ---------------------------------------------------------------------------

const _pool = ' \n\t0123456789.,:;-+*/()[]{}<>=!"\\abcXYZ';

String mutateString(String seed, Random rng, {int maxOps = 8}) {
  final b = seed.split('');
  for (var o = 0, ops = 1 + rng.nextInt(maxOps); o < ops && b.isNotEmpty; o++) {
    final at = rng.nextInt(b.length);
    switch (rng.nextInt(4)) {
      case 0:
        b.removeAt(at);
      case 1:
        b[at] = _pool[rng.nextInt(_pool.length)];
      case 2:
        b.insert(at, _pool[rng.nextInt(_pool.length)]);
      default:
        b[at] = b[at].toUpperCase();
    }
  }
  return b.join();
}

/// Byte mutator biased toward IN-PLACE edits (replace / bit-flip): they keep
/// byte positions stable, which is what lets coverage guidance match positional
/// magic bytes and climb. Structural ops (insert / delete / truncate) still
/// fire ~20% of the time to explore length.
Uint8List mutateBytes(Uint8List seed, Random rng, {int maxOps = 8}) {
  final b = List<int>.of(seed);
  for (var o = 0, ops = 1 + rng.nextInt(maxOps); o < ops && b.isNotEmpty; o++) {
    final at = rng.nextInt(b.length);
    final r = rng.nextInt(10);
    if (r < 5) {
      b[at] = rng.nextInt(256); // replace in place
    } else if (r < 8) {
      b[at] ^= 1 << rng.nextInt(8); // bit-flip in place
    } else if (r == 8) {
      b.insert(at, rng.nextInt(256)); // grow
    } else if (b.length > 1) {
      b.removeAt(at); // shrink
    }
  }
  return Uint8List.fromList(b);
}

Iterable<String> _shrinkString(String s) sync* {
  for (var chunk = s.length ~/ 2; chunk >= 1; chunk ~/= 2) {
    for (var i = 0; i + chunk <= s.length; i += chunk) {
      yield s.substring(0, i) + s.substring(i + chunk);
    }
  }
}

Iterable<Uint8List> _shrinkBytes(Uint8List b) sync* {
  for (var chunk = b.length ~/ 2; chunk >= 1; chunk ~/= 2) {
    for (var i = 0; i + chunk <= b.length; i += chunk) {
      final out = Uint8List(b.length - chunk);
      out.setRange(0, i, b);
      out.setRange(i, out.length, b, i + chunk);
      yield out;
    }
  }
}

T _minimize<T>(
    T input, String type, void Function(T) entry, bool Function(Object) clean) {
  bool fails(T c) {
    try {
      entry(c);
      return false;
    } catch (e) {
      return !clean(e) && e.runtimeType.toString() == type;
    }
  }

  Iterable<T> cands(T x) => x is String
      ? _shrinkString(x).cast<T>()
      : x is Uint8List
          ? _shrinkBytes(x).cast<T>()
          : const Iterable.empty();

  var cur = input;
  for (var improved = true, guard = 0; improved && guard++ < 100000;) {
    improved = false;
    for (final c in cands(cur)) {
      if (fails(c)) {
        cur = c;
        improved = true;
        break;
      }
    }
  }
  return cur;
}

// ---------------------------------------------------------------------------
// VM-service coverage
// ---------------------------------------------------------------------------

Future<VmService> _connectSelf() async {
  final info = await dev.Service.getInfo();
  final uri = info.serverUri;
  if (uri == null) {
    throw StateError('No VM service. Run with:\n'
        '  dart run --enable-vm-service=0 --no-pause-isolates-on-exit <harness>');
  }
  final ws = uri.replace(
    scheme: uri.scheme == 'https' ? 'wss' : 'ws',
    pathSegments: [...uri.pathSegments.where((s) => s.isNotEmpty), 'ws'],
  );
  return vmServiceConnectUri(ws.toString());
}

/// Cumulative covered-token count for the target library, scoped via
/// libraryFilters so the report stays small and fast.
Future<int> _coverageHits(VmService s, String iso, String targetLib) async {
  final report = await s.getSourceReport(
    iso,
    const [SourceReportKind.kCoverage],
    forceCompile: false,
    libraryFilters: [targetLib],
  );
  var hits = 0;
  for (final r in report.ranges ?? const <SourceReportRange>[]) {
    hits += (r.coverage?.hits ?? const []).length;
  }
  return hits;
}

// ---------------------------------------------------------------------------
// Corpus persistence (bytes on disk; String targets are utf8-coded)
// ---------------------------------------------------------------------------

Uint8List _toBytes<T>(T x) =>
    x is Uint8List ? x : Uint8List.fromList(utf8.encode(x.toString()));

T _fromBytes<T>(Uint8List b, T sample) =>
    (sample is String ? utf8.decode(b, allowMalformed: true) : b) as T;

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

class CovFuzzReport {
  final int execs;
  final int corpusSize;
  final int coverage;
  final int newlyCovering; // corpus inputs discovered this run
  final int elapsedMs;
  final Map<String, int> escapes;
  final Map<String, String> minimalRepro;
  final Map<String, int> minimalSize;
  CovFuzzReport(this.execs, this.corpusSize, this.coverage, this.newlyCovering,
      this.elapsedMs, this.escapes, this.minimalRepro, this.minimalSize);

  bool get clean => escapes.isEmpty;

  int report() {
    stdout.writeln('execs=$execs corpus=$corpusSize '
        '(+$newlyCovering new-coverage) coverage=$coverage '
        'elapsed=${elapsedMs}ms');
    if (clean) {
      stdout.writeln('CLEAN: no contract violations.');
      return 0;
    }
    stdout.writeln('ESCAPES (contract violations): $escapes');
    for (final k in minimalRepro.keys) {
      stdout.writeln(
          '  $k — minimal repro (len=${minimalSize[k]}): ${minimalRepro[k]!.replaceAll('\n', '\\n')}');
    }
    return 1;
  }
}

// ---------------------------------------------------------------------------
// The coverage-guided loop
// ---------------------------------------------------------------------------

/// Coverage-guided fuzz of [entry] over inputs evolved from [seeds].
///
/// [targetLib] is the library URI to score coverage on, e.g.
/// `package:my_pkg/src/foo_parser.dart` — the parser you're exercising.
///
/// A [corpusDir] persists new-coverage inputs across runs (OSS-Fuzz style); a
/// [crashDir] saves each distinct escape's minimized reproducer.
Future<CovFuzzReport> covFuzz<T>({
  required List<T> seeds,
  required void Function(T input) entry,
  required T Function(T seed, Random rng) mutate,
  required String targetLib,
  bool Function(Object e)? isClean,
  int iterations = 20000,
  int budgetMs = 60000,
  int seed = 20260718,
  String? corpusDir,
  String? crashDir,
  bool log = false,
}) async {
  final clean = isClean ?? (e) => e is FormatException;
  final rng = Random(seed);
  final s = await _connectSelf();
  final vm = await s.getVM();
  final iso = vm.isolates!.first.id!;

  final escapes = <String, int>{};
  final firstFail = <String, T>{};

  String? runOne(T input) {
    try {
      entry(input);
      return null;
    } catch (e) {
      if (clean(e)) return null;
      return e.runtimeType.toString();
    }
  }

  void record(String type, T input) {
    escapes[type] = (escapes[type] ?? 0) + 1;
    firstFail.putIfAbsent(type, () => input);
  }

  // Corpus = seeds + any persisted corpus files.
  final corpus = <T>[...seeds];
  if (corpusDir != null && seeds.isNotEmpty) {
    final dir = Directory(corpusDir);
    if (dir.existsSync()) {
      for (final f in dir.listSync().whereType<File>()) {
        corpus.add(_fromBytes(f.readAsBytesSync(), seeds.first));
      }
    } else {
      dir.createSync(recursive: true);
    }
  }
  if (crashDir != null) Directory(crashDir).createSync(recursive: true);

  // Warm up on the corpus to establish baseline coverage.
  for (final c in corpus) {
    final esc = runOne(c);
    if (esc != null) record(esc, c);
  }
  var bestCov = await _coverageHits(s, iso, targetLib);
  final baseCorpus = corpus.length;

  final sw = Stopwatch()..start();
  var execs = 0;
  for (var i = 0; i < iterations; i++) {
    final base = corpus[rng.nextInt(corpus.length)];
    final mut = mutate(base, rng);
    final esc = runOne(mut);
    execs++;
    if (esc != null) {
      record(esc, mut);
      if (crashDir != null) {
        File('$crashDir/crash-$esc-${mut.hashCode.toUnsigned(32)}')
            .writeAsBytesSync(_toBytes(mut));
      }
    }
    final cov = await _coverageHits(s, iso, targetLib);
    if (cov > bestCov) {
      bestCov = cov;
      corpus.add(mut); // this input reached new code — keep it
      if (log) {
        stderr.writeln('  exec=$execs coverage=$cov corpus=${corpus.length}'
            '${esc != null ? '  [ESCAPE $esc]' : ''}');
      }
      if (corpusDir != null) {
        File('$corpusDir/cov-${mut.hashCode.toUnsigned(32)}')
            .writeAsBytesSync(_toBytes(mut));
      }
    }
    if (sw.elapsedMilliseconds > budgetMs) {
      stdout.writeln('(time budget hit at exec=$execs)');
      break;
    }
  }

  // Minimize each distinct escape.
  final minimalRepro = <String, String>{};
  final minimalSize = <String, int>{};
  firstFail.forEach((type, input) {
    final m = _minimize(input, type, entry, clean);
    final str = m.toString();
    minimalRepro[type] = str.length > 200 ? '${str.substring(0, 200)}…' : str;
    minimalSize[type] =
        m is String ? m.length : (m is Uint8List ? m.length : -1);
  });

  await s.dispose();
  return CovFuzzReport(execs, corpus.length, bestCov, corpus.length - baseCorpus,
      sw.elapsedMilliseconds, escapes, minimalRepro, minimalSize);
}
