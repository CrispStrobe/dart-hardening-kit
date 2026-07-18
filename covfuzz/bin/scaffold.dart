// Generate a fuzz harness stub in the current package's tool/ dir. Add covfuzz
// as a dev_dependency first (dart pub add -d covfuzz), then fill in the TODOs.
// Usage: covfuzz_scaffold <package-name> <import-path> <name> [--bytes]
import 'dart:io';

void main(List<String> args) {
  final pos = args.where((a) => !a.startsWith('--')).toList();
  if (pos.length < 3) {
    stderr.writeln('usage: covfuzz_scaffold <package-name> <import-path> <name> [--bytes]');
    exit(2);
  }
  final pkg = pos[0], path = pos[1], name = pos[2];
  final bytes = args.contains('--bytes');
  final t = bytes ? 'Uint8List' : 'String';
  final mut = bytes ? 'mutateBytes' : 'mutateString';
  final imp = path.endsWith('.dart') ? path.substring(0, path.length - 5) : path;
  Directory('tool').createSync(recursive: true);
  final out = File('tool/fuzz_$name.dart');
  if (out.existsSync()) {
    stderr.writeln('${out.path} already exists — not overwriting');
    exit(3);
  }
  out.writeAsStringSync('''
// Fuzz harness for $path. Run: dart run tool/fuzz_$name.dart
${bytes ? "import 'dart:typed_data';\n" : ''}import 'package:covfuzz/covfuzz.dart';
import 'package:$pkg/$imp.dart';

void main() {
  final report = fuzz<$t>(
    seeds: [/* TODO: valid input(s) */],
    entry: (input) {
      // TODO: call your parser, e.g. parseFoo(input);
      throw UnimplementedError('wire the entry point');
    },
    mutate: $mut,
    isClean: (e) => e is FormatException, // TODO: add your reject types
  );
  report.report();
}
''');
  stdout.writeln('wrote ${out.path} — edit seeds + entry, then '
      'dart run ${out.path}');
}
