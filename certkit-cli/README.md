# certkit-cli

A command-line interface for [`certkit`](https://crates.io/crates/certkit), the
pure-Rust X.509 toolkit. The installed binary is named `certkit`.

## Install

```sh
cargo install certkit-cli
```

## Usage

Generate a private key (PKCS#8 PEM to stdout, or a file with `--out`):

```sh
certkit generate-key --algorithm ed25519 --out key.pem
```

Create a self-signed certificate (generates a key unless `--key` is given):

```sh
certkit self-signed \
  --common-name example.com \
  --san example.com --san www.example.com \
  --eku server-auth \
  --days 365 \
  --key-out key.pem --out cert.pem
```

Create a self-signed CA, then issue a leaf certificate from it:

```sh
certkit self-signed --common-name "Example CA" --ca \
  --key-out ca.key.pem --out ca.cert.pem

certkit issue \
  --ca-cert ca.cert.pem --ca-key ca.key.pem \
  --common-name server.example.com \
  --san server.example.com --eku server-auth \
  --key-out server.key.pem --out server.cert.pem
```

Inspect a certificate (PEM or DER, auto-detected; reads stdin with `-`):

```sh
certkit inspect cert.pem
certkit inspect cert.pem --fingerprint        # add the SHA-256 fingerprint
certkit inspect cert.der --json               # machine-readable output
cat cert.pem | certkit inspect -
```

Run `certkit <command> --help` for the full set of options.

## Algorithms

`--algorithm` accepts `rsa`, `p256`, `p384`, `p521`, and `ed25519`. RSA key size
is controlled with `--rsa-bits` (default 2048).
