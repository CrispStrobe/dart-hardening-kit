// Prove a hardening guard is load-bearing: revert a marker-wrapped guard, run
// the test expecting FAILURE, restore the file byte-identically.
// Wrap the guard as:  // GUARD:name >>>  … guard code …  // GUARD:name <<<
// Usage: covfuzz_mutverify --file F --guard NAME --test 'CMD'
import 'dart:io';

Future<void> main(List<String> args) async {
  String? file, guard, test;
  for (var i = 0; i + 1 < args.length; i++) {
    if (args[i] == '--file') file = args[i + 1];
    if (args[i] == '--guard') guard = args[i + 1];
    if (args[i] == '--test') test = args[i + 1];
  }
  if (file == null || guard == null || test == null) {
    stderr
        .writeln("usage: covfuzz_mutverify --file F --guard NAME --test 'CMD'");
    exit(2);
  }
  final f = File(file);
  if (!f.existsSync()) {
    stderr.writeln('no such file: $file');
    exit(2);
  }
  final orig = f.readAsStringSync();
  if (!orig.contains('GUARD:$guard >>>')) {
    stderr.writeln(
        "no '// GUARD:$guard >>>' marker in $file — wrap the guard first.");
    exit(3);
  }
  var inb = false;
  final muted = orig.split('\n').map((l) {
    if (l.contains('GUARD:$guard >>>')) return (inb = true, l).$2;
    if (l.contains('GUARD:$guard <<<')) return (inb = false, l).$2;
    return inb ? '// [mutation] $l' : l;
  }).join('\n');
  f.writeAsStringSync(muted);
  stdout
      .writeln("→ guard '$guard' reverted; running test (expecting FAILURE)…");
  try {
    final r = await Process.run('bash', ['-c', test]);
    if (r.exitCode == 0) {
      stdout.writeln('MUTATION NOT CAUGHT — the test still passed with the '
          'guard removed. Strengthen the test.');
      exitCode = 1;
    } else {
      stdout.writeln('mutation caught — test failed with the guard removed '
          '(as intended). File restored byte-identically.');
    }
  } finally {
    f.writeAsStringSync(orig);
  }
}
