# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `certkit-cli`: a `cert_info` subcommand that parses a certificate (PEM or DER,
  or stdin via `-`) and prints its subject, issuer, serial, validity, public
  key, signature algorithm, and decoded extensions. Supports `--fingerprint`
  (SHA-256 of the DER) and `--json` for machine-readable output.
- `certkit-cli`: `--email` for rfc822 Subject Alternative Names.

### Changed

- **`certkit-cli`: the command and argument surface now mirrors Botan's CLI.**
  These are breaking changes for the unreleased CLI:
  - Subcommands renamed: `generate-key` → `keygen`, `self-signed` →
    `gen_self_signed`, `inspect` → `cert_info` (`issue` is unchanged).
  - Key selection uses Botan's vocabulary: `--algorithm`/`-a` (alias `--algo`)
    takes `RSA`, `ECDSA`, or `Ed25519`, and the key shape is chosen with
    `--params` (RSA bits, e.g. `3072`, or an ECDSA curve, e.g. `secp256r1`).
    The previous `p256`/`p384`/`p521` values and the `--rsa-bits` flag are gone.
  - The subject common name is now a positional argument instead of
    `--common-name`.
  - `--san` is replaced by `--dns` (DNS names) and `--email` (rfc822 names).

## [0.1.2]

### Added

- Per-algorithm Cargo features (`rsa`, `p256`, `p384`, `p521`, `ed25519`),
  all enabled by default. Set `default-features = false` and opt in to drop
  algorithms you don't use, for example, to build without RSA and its
  `num-bigint-dig`/`libm` dependency tree. See the README for details.
- A compile error is now raised when no algorithm feature is enabled.
- `compile_feature_combinations.sh` and a CI step that builds a representative
  set of feature combinations.

### Changed

- **`PublicKey::to_der()` for ECDSA P-256 now returns the SEC1 point encoding**,
  matching the existing P-384 and P-521 behaviour. Previously it emitted a
  different (PKCS#1-style) encoding that was inconsistent with the other curves.
  Callers that persisted or compared the old P-256 output should re-check it.

### Notes

- This release is backwards compatible for the default feature set: building
  `certkit` without changing features behaves as before.
