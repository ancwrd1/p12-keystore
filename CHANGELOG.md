# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-10-09

### Added

- `Pkcs12Archive::from_pkcs12` exposes the decoded private keys, certificates and secrets
  (`PrivateKeyBag`, `CertificateBag`, `SecretBag`) before import policies are applied,
  retaining duplicates and friendly-name collisions (#13).

### Fixed

- `KeyStore::from_pkcs12` no longer overwrites imported entries with colliding aliases;
  duplicates are kept with `#2`, `#3`, ... suffixes (#13).

## [0.3.2] - 2026-09-14

### Added

- Verification of traditional PKCS#12 MACs using SHA-2 hash OIDs (SHA-224 through SHA-512/256,
  as produced by OpenSSL `-macalg`), and the same set of algorithms in `MacAlgorithm` for writing (#12).

### Security

- Bound attacker-controlled work factors during import: MAC, PBES1 and PBKDF2 iteration counts
  above 1,000,000, scrypt memory cost above 1 GiB and scrypt parallelism above 16 are rejected
  with `Error::InvalidParameters` (#11).
- Break certificate chain resolution on issuer cycles, which previously caused unbounded
  memory growth (#11).

## [0.3.1] - 2026-06-19

### Fixed

- Re-export the `PrivateKey` struct (#10).

## [0.3.0] - 2026-06-07

### Added

- `PrivateKey` and `LocalKeyId` types.
- Support for unencrypted key bags (`keyBag`) and for bundles without a link between keys
  and certificates (#7).

### Changed

- **Breaking:** refactored the `PrivateKeyChain` API: `new` now takes `(local_key_id, key: PrivateKey, certs)`,
  `key()` returns `&PrivateKey`, `chain()` is renamed to `certs()`, and `local_key_id()` returns `&LocalKeyId`.
- Minimum supported Rust version set to 1.85 (#8).

## [0.2.0] - 2025-07-08

### Added

- Support for secret keys (AES, RC4, HMAC etc.), including reading and writing them
  in PKCS#12 files, and replaceable random generators.

## [0.1.5] - 2025-04-01

### Fixed

- Avoid duplicated self-signed certificates.

## [0.1.4] - 2025-01-29

### Changed

- Updated dependencies.

## [0.1.3] - 2024-05-20

### Fixed

- Compilation errors with older Rust versions (#1).

## [0.1.2] - 2024-04-03

### Added

- `private_key_chain` method.
- `pbes1` feature flag (enabled by default) to make the legacy PBES1 algorithms optional.

### Changed

- `MacAlgorithm` is now non-exhaustive.
- Internal refactorings.

## [0.1.1] - 2024-03-19

- Minor fixes after the initial release.

## [0.1.0] - 2024-03-19

- Initial release.

[Unreleased]: https://github.com/ancwrd1/p12-keystore/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/ancwrd1/p12-keystore/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/ancwrd1/p12-keystore/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/ancwrd1/p12-keystore/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ancwrd1/p12-keystore/compare/v0.1.5...v0.2.0
[0.1.5]: https://github.com/ancwrd1/p12-keystore/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/ancwrd1/p12-keystore/compare/0.1.3...v0.1.4
[0.1.3]: https://github.com/ancwrd1/p12-keystore/compare/0.1.2...0.1.3
[0.1.2]: https://github.com/ancwrd1/p12-keystore/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/ancwrd1/p12-keystore/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/ancwrd1/p12-keystore/releases/tag/0.1.0
