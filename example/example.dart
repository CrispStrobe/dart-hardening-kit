import 'dart:typed_data';
import 'package:covfuzz/covfuzz.dart';

// A parser with a deliberate bug: it trusts a length byte from the input.
void parse(Uint8List b) {
  if (b.isEmpty) throw const FormatException('empty');
  final n = b[0];
  Uint8List.sublistView(b, 0, n); // RangeError when n > b.length
}

void main() {
  final report = fuzz<Uint8List>(
    seeds: [
      Uint8List.fromList([2, 0, 0])
    ],
    entry: parse,
    mutate: mutateBytes,
    iterations: 5000,
  );
  // Prints the escape and its minimized reproducer; exit 1 = a contract leak.
  report.report();
}
