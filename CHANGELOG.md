# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0]

This release is a correctness and security pass over certificate issuance.
Several operations that previously produced invalid certificates or panicked now
do the right thing, and the library API is reworked to return `Result` instead
of panicking.

### Fixed

- **ECDSA signatures are now DER-encoded** (`ECDSA-Sig-Value SEQUENCE { r, s }`)
  rather than the fixed-width `r‖s` form. The old encoding is rejected by X.509
  verifiers, so ECDSA certificates issued by previous versions failed signature
  validation.
- **P-384 and P-521 certificates now use, and declare, SHA-384 / SHA-512** to
  match the curve (RFC 5480). Previously every ECDSA curve was signed with
  SHA-256 while the certificate still advertised it, and P-384 / P-521
  certificates could not be parsed back (`Unsupported signature algorithm`).
- **Distinguished names no longer panic or allow RDN injection.** Subject and
  issuer names are built structurally instead of by formatting the fields into an
  RFC 4514 string and re-parsing. Values containing metacharacters (`,`, `+`,
  `=`, `"`, `\`, `<`, `>`, `;`, a leading `#`/space, ...) — e.g. an organization
  name like `Acme, Inc.` previously panicked or silently injected extra
  attributes (a common name of `a,O=Evil` could forge an Organization); they are
  now carried verbatim. Names whose attributes are encoded as `PrintableString`
  or `IA5String` (not just `UTF8String`), such as a Country, now parse instead of
  panicking.
- **Key usage is correct for modern algorithms.** End-entity authentication
  certificates always assert `digitalSignature`, and `keyEncipherment` is set
  only for RSA keys — it is meaningless for ECDSA / Ed25519 and broke TLS 1.3
  handshakes when asserted.
- Subject Alternative Name IP addresses are encoded as `IPAddress` and email
  addresses as `rfc822Name`, instead of every entry being mis-encoded as
  `DNSName`.
- RSA private keys in PKCS#1 DER now import correctly; the public half is derived
  from the private key rather than requiring the same bytes to also decode as a
  public key (which never succeeded).
- Issuing or encoding a certificate with an out-of-range serial number, or with a
  far-future validity date, returns an error instead of panicking. Validity dates
  from 2050 onward are encoded as `GeneralizedTime` per RFC 5280 §4.1.2.5.
- Parsing a certificate that carries no extensions no longer panics.
- Non-RSA feature builds (e.g. `--no-default-features --features p256`) compile
  again.

### Added

- `Certificate::from_der`, `Certificate::from_pem`, and `Certificate::from_bytes`
  (which auto-detects PEM vs DER) for parsing existing certificates.
- `Certificate::fingerprint` — the SHA-256 digest of the DER encoding, matching
  `openssl x509 -fingerprint -sha256`.
- Issued certificates now carry a **Subject Key Identifier** in addition to an
  **Authority Key Identifier**, so a chain links up: a certificate's AKI key id
  matches its issuer's SKI key id (RFC 5280 §4.2.1.1/§4.2.1.2). A new
  `SubjectKeyIdentifier` extension type is exposed.
- `CertificateParams` gained `max_path_length: Option<u8>`; CA certificates emit
  a Basic Constraints `pathLenConstraint` when it is set.
- `KeyPair::encode_private_key_der` — PKCS#8 DER export, the binary counterpart to
  `encode_private_key_pem`.
- `KeyType` enum plus `KeyPair::key_type` and `PublicKey::key_type` for inspecting
  a key's algorithm without matching on the full enum, and `PublicKey::as_spki`.
- `Validity::new` (explicit bounds), `Validity::duration`, and
  `Validity::remaining`.
- `Display` implementations for `KeyPair`, `KeyType`, and `SignatureAlgorithm`.
- Lightweight `log` instrumentation across key generation, issuance, and
  encoding.
- `tests/tls_echo.rs`: a runnable end-to-end example that builds a
  Root → Intermediate → leaf chain and verifies a mutual-TLS echo round-trip with
  `rustls` (RSA, P-256, P-384, and Ed25519).
- CI now also runs clippy (`-D warnings`), rustfmt, a doc build (`-D warnings`),
  and an MSRV (1.85) check alongside the existing feature-combination gate.

### Changed

- **Library API (breaking, pre-1.0):**
  - `CertificationRequestInfo` is renamed to `CertificateParams`, and
    `Certificate::to_cert_info` to `Certificate::params`.
  - `SignatureAlgorithm::Sha256WithEdDSA` is renamed to `SignatureAlgorithm::Ed25519`.
  - `PublicKey::from_der` is renamed to `PublicKey::from_rsa_pkcs1_der`, making
    its RSA/PKCS#1-only scope explicit.
  - `SubjectAltName` replaces its single `names` list with separate `dns_names`,
    `ip_addresses` (`Vec<IpAddr>`), and `email_addresses` fields.
  - `BasicConstraints.max_path_length` is now `Option<u8>` (was `Option<u32>`,
    which truncated when encoded).
  - `AuthorityKeyIdentifier`'s `authority_cert_issuer` and
    `authority_cert_serial_number` are now `Option`, preserved when present in a
    parsed certificate rather than required.
  - `Validity` stores its bounds as pre-encoded `x509_cert::time::Time` (read via
    `not_before()` / `not_after()`) instead of public `OffsetDateTime` fields.
  - Operations that can fail now return `Result` instead of panicking:
    `Certificate::new_self_signed` / `new_self_signed_with_expiration`,
    `Issuer::issue`, `Issuer::issuer_name`, `ExtensionParam::from_extension`,
    `DistinguishedName::as_x509_name` / `from_x509_name`, and `Validity::for_days`.
  - `Issuer::serial_number` now has a default implementation (a 20-byte CSPRNG
    serial) that can be overridden. The inner fields of `Certificate` and
    `CertificateWithPrivateKey` are now private, with
    `new` / `cert` / `key` / `into_parts` accessors.
- Serial numbers are now 20-byte CSPRNG values (RFC 5280 §4.1.2.2) instead of a
  fixed `1`.
- `KeyPair::generate_rsa` rejects key sizes below 2048 bits, and `KeyPair`'s
  `Debug` output no longer includes private key material.
- Documentation clarifies that CertKit builds and parses certificates and keys
  but does not verify signatures or perform certificate-path validation; pair it
  with a verifier such as `rustls` / `webpki` to validate a chain.
- The OpenSSL- and Botan-based dev-dependency tests are replaced by the pure-Rust
  `rustls` integration test. The `regex`, `base64`, `rand`, and `ecdsa`
  dependencies are dropped, and `thiserror` is updated to 2.x.

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
