// Does a lib file fuzz under bare `dart run`, or is it FFI-blocked?
// Usage: covfuzz_probe <repo-dir> <package-name> <import-path>
import 'dart:io';

Future<void> main(List<String> args) async {
  if (args.length < 3) {
    stderr.writeln(
        'usage: covfuzz_probe <repo-dir> <package-name> <import-path>');
    exit(2);
  }
  final repo = args[0], pkg = args[1], path = args[2];
  if (!File('$repo/pubspec.yaml').existsSync()) {
    stderr.writeln('no pubspec.yaml in $repo');
    exit(2);
  }
  Directory('$repo/tool').createSync(recursive: true);
  final rel = 'tool/.probe_$pid.dart';
  final probe = File('$repo/$rel');
  final imp =
      path.endsWith('.dart') ? path.substring(0, path.length - 5) : path;
  probe.writeAsStringSync(
      "import 'package:$pkg/$imp.dart';\nvoid main() { print('FUZZABLE_OK_MARKER'); }\n");
  await Process.run('dart', ['pub', 'get'], workingDirectory: repo);
  final r = await Process.run('dart', ['run', rel], workingDirectory: repo);
  if (probe.existsSync()) probe.deleteSync();
  final out = '${r.stdout}${r.stderr}';
  if (out.contains('FUZZABLE_OK_MARKER')) {
    stdout.writeln('FUZZABLE   $path');
  } else if (RegExp("is not a subtype of type 'FunctionType'"
          r"|_FfiUseSiteTransformer|dart:ffi")
      .hasMatch(out)) {
    stdout.writeln('FFI-BLOCKED $path — extract the pure logic into a '
        'standalone copy first');
  } else {
    stdout.writeln('OTHER-ERROR $path');
    stdout.writeln(out.split('\n').take(3).map((l) => '    $l').join('\n'));
  }
}
