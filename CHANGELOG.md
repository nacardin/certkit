# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `certkit-cli`, a `certkit` binary with `keygen`, `gen_self_signed`, `issue`,
  and `cert_info` subcommands modelled on Botan's CLI. Generated private keys are
  written `0600` on Unix.

### Fixed

- `Validity::for_days` now returns `CertKitError::InvalidInput` for periods that
  cannot be represented, instead of panicking on arithmetic overflow.

## [0.2.0]

This release focuses on correctness, security, and returning `Result` instead of panicking.

### Fixed

- DER-encode ECDSA signatures instead of using fixed-width format.
- Use and declare matching SHA-384 / SHA-512 signatures for P-384 and P-521 curves.
- Build Distinguished Names structurally to prevent RDN injection and panics.
- Set digital signature key usage correctly for non-RSA algorithms.
- Encode IP and email SANs using IPAddress and rfc822Name types instead of DNSName.
- Fix import of RSA private keys in PKCS#1 DER format.
- Return errors instead of panicking for invalid serial numbers or far-future validity dates.
- Fix panic when parsing certificates without extensions.

### Added

- Add certificate parsing functions from DER, PEM, or auto-detected bytes.
- Add `Certificate::fingerprint` to compute SHA-256 digests.
- Add Subject Key Identifier and Authority Key Identifier extensions to issued certificates.
- Add `max_path_length` to `CertificateParams` for path constraints.
- Add `KeyPair::encode_private_key_der` for PKCS#8 DER export.
- Add `KeyType` enum and helper methods for key algorithm inspection.
- Add validity bounds, duration, and remaining helper methods.
- Add `Display` implementations for key pairs, types, and signature algorithms.
- Add light log instrumentation for key and certificate operations.
- Add an integration test verifying end-to-end TLS echo round-trips.
- Expand CI checks with clippy, rustfmt, docs, and MSRV validation.

### Changed

- Rename and restructure public library APIs to return `Result` and improve parameter structures.
- Use random 20-byte CSPRNG serial numbers by default.
- Prevent RSA key generation under 2048 bits and strip private keys from debug output.
- Replace OpenSSL and Botan test dependencies with pure Rust integration tests and reduce dependencies.

## [0.1.2]

### Added

- Add Cargo features for individual cryptographic algorithms.
- Raise a compile error if no cryptographic algorithm features are enabled.
- Add a script and CI step to build different feature combinations.

### Changed

- Change P-256 public key DER serialization to use SEC1 point encoding.

## [0.1.1]

### Fixed

- Correctly propagate the `is_ca` flag to basic constraints in issued certificates.
- Fix signature algorithm OID encoding for issued certificates.
- Fix test execution under non-English locales and newer OpenSSL versions.

### Added

- Add `KeyPair::encode_private_key_pem` to export private keys in PEM format.
- Add `Certificate::new_self_signed_with_expiration` for custom validity dates.

## [0.1.0]

### Added

- Initial release implementing core X.509 certificate and key pair generation.
- Support key generation and management for RSA, ECDSA (P-256/P-384/P-521), and Ed25519.
- Support PEM/DER encoding for certificates and public/private keys.
- Add basic certificate extension support including Basic Constraints, Key Usage, and SAN.
