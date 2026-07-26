# Changelog

All notable changes to this project will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project intends to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Contract values now match the JSON Schema lexically: version, status, evidence state, and
  lowercase SHA-256 values are never whitespace-normalized.
- The PEP 517 backend is exactly pinned and present in the locked development environment.

### Security

- Check output cannot replace discovered report-shaped JSON or any referenced evidence path.
- Finding, manifest, evidence-root, evidence, and output traversal rejects symlinked ancestors
  and detects component replacement between inspection and descriptor open.
- Every ordinary YAML constructor failure is normalized to a parse error without a traceback.
- Direct construction of exported result models now preserves deep immutability.

## [0.1.0] - 2026-07-26

### Added

- Markdown YAML-frontmatter and JSON finding parsers for schema version `0.1`.
- Deterministic `PL001`–`PL010` evidence-hygiene rules.
- Root-confined SHA-256 manifest generation and tamper verification.
- Text, JSON, and SARIF 2.1.0 reporters.
- `init`, `check`, `manifest`, and `verify` commands with stable exit codes.
- Typed Python API, synthetic examples, schemas, documentation, and offline test suite.
- Bounded duplicate-key-safe parsers, descriptor-held evidence hashing, deep-frozen models,
  and atomic output protection against symlink and input-overwrite races.

[Unreleased]: https://github.com/3nesdeniz/prooflint/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/3nesdeniz/prooflint/releases/tag/v0.1.0
