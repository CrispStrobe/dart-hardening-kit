/// Reader-robustness fuzzing for Dart parsers, in two tiers:
///
/// - [fuzz] — blind mutation, zero setup, ~1M execs/sec. The fast first pass:
///   it shakes out crashes and the slow-parse (bomb) signal, and minimizes each
///   escape to a small reproducer.
/// - [covFuzz] — coverage-guided corpus evolution via the VM service, for the
///   deep paths behind magic checks and preconditions that blind mutation can't
///   reach. Slower; must run with `--enable-vm-service`.
///
/// Both take a parse entry point, valid seeds, and a clean-reject allow-list,
/// and treat any other thrown exception as a contract violation.
library;

export 'src/blind.dart';
export 'src/coverage.dart';
export 'src/mutators.dart';
