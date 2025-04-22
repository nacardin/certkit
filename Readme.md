# CertKit

A high-level Rust library providing abstractions over certificates and keys. This toolkit simplifies the process of creating certificates, intermediate Certificate Authorities (CAs), and root CAs.

## Features

- Create and manage X.509 certificates
- Generate and handle root Certificate Authorities (CAs)
- Create intermediate CAs for certificate hierarchies
- Support for multiple key types:
  - RSA
  - ECDSA (P-256)
  - Ed25519
- PEM and DER format support
- Modern Rust implementation with strong type safety
- Zero-copy parsing and serialization with `der` crate

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
certkit = "0.1.0"
```

## Dependencies

- `x509-cert`: X.509 certificate handling
- `der`: ASN.1 DER encoding/decoding
- `pkcs8`: Private key cryptography standard
- `rsa`, `p256`, `ed25519-dalek`: Cryptographic algorithms
- `time`: Time handling for certificate validity
- `pem`: PEM format encoding/decoding

### License

This crate is distributed under the terms of both the MIT license and the Apache License (Version 2.0), at your option.

See [LICENSE](LICENSE) for details.

### License of your contributions

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
