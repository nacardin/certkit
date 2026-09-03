# certkit-cli

A command-line interface for [`certkit`](https://crates.io/crates/certkit), the
pure-Rust X.509 toolkit. The installed binary is named `certkit`.

## Install

```sh
cargo install certkit-cli
```

The subcommand names and most arguments mirror [Botan's](https://botan.randombit.net/)
CLI (`keygen`, `gen_self_signed`, `issue`, `cert_info`), so existing Botan
muscle memory mostly transfers.

## Usage

Generate a private key (PKCS#8 PEM to stdout, or a file with `--out`):

```sh
certkit keygen --algo Ed25519 --out key.pem
certkit keygen --algo RSA --params 3072 --out key.pem
```

Create a self-signed certificate (generates a key unless `--key` is given). The
common name is positional, as in Botan:

```sh
certkit gen_self_signed example.com \
  --dns example.com --dns www.example.com \
  --ip 192.168.1.10 --ip ::1 \
  --email admin@example.com \
  --eku server-auth \
  --days 365 \
  --key-out key.pem --out cert.pem
```

Create a self-signed CA, then issue a leaf certificate from it:

```sh
certkit gen_self_signed "Example CA" --ca \
  --key-out ca.key.pem --out ca.cert.pem

certkit issue server.example.com \
  --ca-cert ca.cert.pem --ca-key ca.key.pem \
  --dns server.example.com --eku server-auth \
  --key-out server.key.pem --out server.cert.pem
```

Inspect a certificate (PEM or DER, auto-detected; reads stdin with `-`):

```sh
certkit cert_info cert.pem
certkit cert_info cert.pem --fingerprint      # add the SHA-256 fingerprint
certkit cert_info cert.der --json             # machine-readable output
cat cert.pem | certkit cert_info -
```

Run `certkit <command> --help` for the full set of options.

## Scope

This is a small tool covering the common "make me a key and a certificate" cases.
**Not** supported yet:

- **Certificate signing requests** — no equivalent of Botan's `gen_pkcs10` /
  `sign_cert`. Keys and certificates are always generated together, so certkit
  cannot currently act as a CA for a CSR produced elsewhere.
- **Explicit key usage** — the key usage extension is derived from `--ca` and the
  key algorithm; it cannot be set directly.
- **Path length constraints** — `--ca` always issues a CA without a `pathLenConstraint`,
  though the library's `CertificateParams` supports `max_path_length`.
- **Absolute validity dates** — validity is `--days` from now; there is no
  `--not-before` / `--not-after`.

`certkit cert_info` prints certificates but does **not** verify them. The library
builds and parses X.509; it does not do signature or path validation. 
