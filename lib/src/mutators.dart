// Mutation operators and delta-debugging crash minimization, shared by the
// blind (`fuzz`) and coverage-guided (`covFuzz`) runners.

import 'dart:math';
import 'dart:typed_data';

const _pool = ' \n\t0123456789.,:;-+*/()[]{}<>=!"\\abcXYZ';

/// One mutation of a String seed: delete / replace / insert / uppercase.
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

/// One mutation of a byte seed, biased toward IN-PLACE edits (replace /
/// bit-flip): they keep byte positions stable, which is what lets coverage
/// guidance match positional magic bytes and climb. Structural ops (insert /
/// delete) still fire ~20% of the time to explore length. Seed from a VALID
/// encoding so mutations keep enough structure to reach deep parse paths.
Uint8List mutateBytes(Uint8List seed, Random rng, {int maxOps = 8}) {
  final b = List<int>.of(seed);
  for (var o = 0, ops = 1 + rng.nextInt(maxOps); o < ops && b.isNotEmpty; o++) {
    final at = rng.nextInt(b.length);
    final r = rng.nextInt(10);
    if (r < 5) {
      b[at] = rng.nextInt(256);
    } else if (r < 8) {
      b[at] ^= 1 << rng.nextInt(8);
    } else if (r == 8) {
      b.insert(at, rng.nextInt(256));
    } else if (b.length > 1) {
      b.removeAt(at);
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

/// Reduce [input] to a minimal reproducer that still throws the same escape
/// type ([type]) via delta-debugging. Auto-shrinks String and Uint8List; other
/// types are returned unchanged.
T minimize<T>(
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
