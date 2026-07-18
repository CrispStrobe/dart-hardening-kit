// Enumerate a tree's Dart packages and their untrusted-input parse entry points
// (byte readers, parseXxx(String), fromJson). Usage: covfuzz_discover [root]
import 'dart:io';

final _entry = RegExp(
  r'(\b[A-Za-z_]\w*\s*\((Uint8List|List<int>)\s)'
  r'|(parse\w*\s*\(\s*String\s)'
  r'|(factory\s+\w+\.fromJson)');

String _pkgName(File p) {
  for (final l in p.readAsLinesSync()) {
    if (l.startsWith('name:')) return l.substring(5).trim();
  }
  return '?';
}

void main(List<String> args) {
  final root = args.isEmpty ? Directory.current.path : args[0];
  for (final d in Directory(root).listSync().whereType<Directory>()) {
    final pubspec = File('${d.path}/pubspec.yaml');
    final lib = Directory('${d.path}/lib');
    if (!pubspec.existsSync() || !lib.existsSync()) continue;
    final hits = <String>[];
    var ffi = false;
    for (final f in lib.listSync(recursive: true).whereType<File>()) {
      if (!f.path.endsWith('.dart') ||
          f.path.endsWith('_test.dart') ||
          f.path.endsWith('.g.dart')) continue;
      final lines = f.readAsLinesSync();
      for (var i = 0; i < lines.length; i++) {
        final l = lines[i];
        if (l.contains('dart:ffi') || l.contains('NativeCallable')) ffi = true;
        if (l.trimLeft().startsWith('//')) continue;
        if (_entry.hasMatch(l)) {
          hits.add('  ${f.path.substring(lib.path.length + 1)}:'
              '${i + 1}: ${l.trim()}');
        }
      }
    }
    if (hits.isEmpty) continue;
    stdout.writeln('### ${d.path.split('/').last}   package=${_pkgName(pubspec)}'
        '${ffi ? '   (uses dart:ffi — probe before you fuzz)' : ''}');
    hits.take(40).forEach(stdout.writeln);
    stdout.writeln();
  }
}
