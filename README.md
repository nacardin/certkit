# CertKit

A high-level Rust library providing abstractions over certificates and keys. This toolkit simplifies the process of creating certificates, intermediate Certificate Authorities (CAs), and root CAs.

## Features

- Create and manage X.509 certificates
- Generate and handle root Certificate Authorities (CAs)
- Create intermediate CAs for certificate hierarchies
- Support for multiple key types:
  - RSA
  - ECDSA (P-256, P-384, P-521)
  - Ed25519
- PEM and DER format support
- Modern Rust implementation with strong type safety
- Zero-copy parsing and serialization with `der` crate

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
certkit = "0.1"
```

## CLI

[`certkit-cli`](certkit-cli/) is a CLI that installs a `certkit` binary for generating keys and certificates. See its [README](certkit-cli/README.md) for usage.

## Cargo features

Each cryptographic algorithm is behind its own feature. All are enabled by default, so the default build is unchanged:

| Feature   | Algorithm        | Default |
|-----------|------------------|---------|
| `rsa`     | RSA              | yes     |
| `p256`    | ECDSA P-256      | yes     |
| `p384`    | ECDSA P-384      | yes     |
| `p521`    | ECDSA P-521      | yes     |
| `ed25519` | Ed25519          | yes     |

To pull in only the algorithms you need, disable the defaults and opt back in. For example, an ECDSA-only build that drops RSA (and its `num-bigint-dig` / `libm` dependency tree):

```toml
[dependencies]
certkit = { version = "0.1", default-features = false, features = ["p256", "p384"] }
```

At least one algorithm feature must be enabled; building with none is a compile error.

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
