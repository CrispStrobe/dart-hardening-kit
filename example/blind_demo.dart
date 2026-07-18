import 'dart:math';
import 'dart:typed_data';
import 'package:covfuzz/covfuzz.dart';
import 'package:covfuzz/src/demo_target.dart';

void main() {
  final rng = Random(1);
  final seed = Uint8List.fromList(List.filled(8, 0));
  var found = 0;
  final sw = Stopwatch()..start();
  for (var i = 0; i < 500000; i++) {
    try {
      deepParse(mutateBytes(seed, rng));
    } on FormatException {
      // clean reject — not a bug
    } catch (_) {
      found++;
    }
  }
  print(
      'BLIND: 500k mutations, RangeErrors found = $found  [${sw.elapsedMilliseconds}ms]');
}
