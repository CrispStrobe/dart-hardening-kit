# dart-hardening-kit

This repository hosts **[covfuzz](covfuzz/)** — a reader-robustness fuzzing
package for Dart parsers: a library with two tiers (blind `fuzz` and
coverage-guided `covFuzz`, both with crash minimization) plus command-line tools
for discovery, fuzzability probing, harness scaffolding, and guard
mutation-testing.

See **[covfuzz/README.md](covfuzz/README.md)**.

```yaml
dev_dependencies:
  covfuzz: ^0.1.0
```

Earlier revisions shipped the tools as standalone shell scripts; they have been
folded into the `covfuzz` package (a Dart library + CLI executables). MIT.
