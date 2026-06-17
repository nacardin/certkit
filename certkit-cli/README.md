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

## Algorithms

`--algorithm` (alias `--algo`, short `-a`) accepts `RSA`, `ECDSA`, and
`Ed25519` (case-insensitive). The key shape is set with `--params`, following
Botan:

- `--algo RSA --params 3072` — RSA key size in bits (default 2048).
- `--algo ECDSA --params secp256r1` — curve `secp256r1`, `secp384r1`, or
  `secp521r1` (default `secp256r1`).
- `--algo Ed25519` — no parameters.
