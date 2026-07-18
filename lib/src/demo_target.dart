import 'dart:typed_data';

// A parser with a bug behind a 4-byte "FUZZ" magic — the canonical example of
// why coverage guidance beats blind mutation. Blind fuzzing must produce all
// four magic bytes AND a bad length in a single mutation (~2^-32); coverage
// guidance earns each matched byte as new coverage and climbs to the bug.
void deepParse(Uint8List b) {
  if (b.isEmpty || b[0] != 0x46) return; // 'F'
  if (b.length < 2 || b[1] != 0x55) return; // 'U'
  if (b.length < 3 || b[2] != 0x5A) return; // 'Z'
  if (b.length < 4 || b[3] != 0x5A) return; // 'Z'
  if (b.length < 5) return;
  final n = b[4];
  Uint8List.sublistView(b, 0, n); // BUG: RangeError when n > b.length
}
