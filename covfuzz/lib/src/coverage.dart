// Coverage-guided corpus-evolution fuzzing. Reads the target library's
// coverage from the VM service after each input; an input that raises the
// cumulative coverage is kept as a corpus seed, so the corpus evolves toward
// deep code — the libFuzzer/AFL loop on the signal Dart exposes.
//
// MUST run with the VM service enabled:
//   dart run --enable-vm-service=0 --no-pause-isolates-on-exit <harness>
//
// The target runs in-process, so a hard hang (a synchronous infinite loop)
// freezes the fuzzer. Shake hangs out with the blind `fuzz` first (it reports
// the slow-parse signal), then run `covFuzz` to reach depth. Coverage is
// process-global and cumulative — run each session in its own process.

import 'dart:convert';
import 'dart:developer' as dev;
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:vm_service/vm_service.dart';
import 'package:vm_service/vm_service_io.dart';

import 'mutators.dart';

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

/// Cumulative covered-token count for [targetLib], scoped via libraryFilters so
/// the report stays small and fast.
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

Uint8List _toBytes<T>(T x) =>
    x is Uint8List ? x : Uint8List.fromList(utf8.encode(x.toString()));

T _fromBytes<T>(Uint8List b, T sample) =>
    (sample is String ? utf8.decode(b, allowMalformed: true) : b) as T;

class CovFuzzReport {
  final int execs;
  final int corpusSize;
  final int coverage;
  final int newlyCovering;
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
      stdout.writeln('  $k — minimal repro (len=${minimalSize[k]}): '
          '${minimalRepro[k]!.replaceAll('\n', '\\n')}');
    }
    return 1;
  }
}

/// Coverage-guided fuzz of [entry] over inputs evolved from [seeds].
///
/// [targetLib] is the library URI to score coverage on, e.g.
/// `package:my_pkg/src/foo_parser.dart`. A [corpusDir] persists new-coverage
/// inputs across runs; a [crashDir] saves each escape's minimized reproducer.
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
      return clean(e) ? null : e.runtimeType.toString();
    }
  }

  void record(String type, T input) {
    escapes[type] = (escapes[type] ?? 0) + 1;
    firstFail.putIfAbsent(type, () => input);
  }

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

  for (final c in corpus) {
    final esc = runOne(c);
    if (esc != null) record(esc, c);
  }
  var bestCov = await _coverageHits(s, iso, targetLib);
  final baseCorpus = corpus.length;

  final sw = Stopwatch()..start();
  var execs = 0;
  for (var i = 0; i < iterations; i++) {
    final mut = mutate(corpus[rng.nextInt(corpus.length)], rng);
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
      corpus.add(mut);
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

  final minimalRepro = <String, String>{};
  final minimalSize = <String, int>{};
  firstFail.forEach((type, input) {
    final m = minimize(input, type, entry, clean);
    final str = m.toString();
    minimalRepro[type] = str.length > 200 ? '${str.substring(0, 200)}…' : str;
    minimalSize[type] =
        m is String ? m.length : (m is Uint8List ? m.length : -1);
  });

  await s.dispose();
  return CovFuzzReport(execs, corpus.length, bestCov, corpus.length - baseCorpus,
      sw.elapsedMilliseconds, escapes, minimalRepro, minimalSize);
}
