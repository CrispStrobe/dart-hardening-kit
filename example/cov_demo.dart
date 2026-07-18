import 'dart:typed_data';
import 'package:covfuzz/covfuzz.dart';
import 'package:covfuzz/src/demo_target.dart';

Future<void> main() async {
  final r = await covFuzz<Uint8List>(
    seeds: [Uint8List.fromList(List.filled(8, 0))],
    entry: deepParse,
    mutate: mutateBytes,
    targetLib: 'package:covfuzz/src/demo_target.dart',
    iterations: 40000,
    budgetMs: 200000,
    log: true, // show the coverage climb
  );
  print('COVERAGE-GUIDED:');
  r.report();
}
