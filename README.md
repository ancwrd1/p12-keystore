# PKCS#12 library written in pure Rust

[![github actions](https://github.com/ancwrd1/p12-keystore/workflows/CI/badge.svg)](https://github.com/ancwrd1/p12-keystore/actions)
[![crates](https://img.shields.io/crates/v/p12-keystore.svg)](https://crates.io/crates/p12-keystore)
[![license](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![docs.rs](https://docs.rs/p12-keystore/badge.svg)](https://docs.rs/p12-keystore)

## Overview

This project contains a simple to use high-level library to work with PKCS#12/PFX keystores, written in pure Rust,
modeled after Java KeyStore API.

Features:

* Single- and multi-keychain PKCS#12
* Support for 'truststores' with only CA root certificates
* Modern and legacy encryption schemes
* Able to read and write Java-compatible keystores
* Support for secret keys and generation of secret keys compatible to Java

Limitations:

* MD5-based encryption schemes are not supported
* Single password is used to encrypt both private keys and certificate data in one store
* Non-encrypted stores are not supported

[Documentation](https://docs.rs/p12-keystore)

For applications that need to validate every certificate bag before chain
construction, `Pkcs12Archive::from_pkcs12` exposes decoded private keys,
certificates, and secrets before import policies are applied. The collections
retain duplicates and friendly-name collisions. This API verifies a MAC when
present and decrypts supported bags; certificate validation is left to callers.

`KeyStore::from_pkcs12` retains colliding aliases using `#2`, `#3`, etc. suffixes
instead of overwriting imported entries. Its `Strict` policy still filters
unmatched keys and untrusted certificates as before.

Usage example:

```rust,no_run
use p12_keystore::{KeyStore, Pkcs12ImportPolicy};

const PASSWORD: &str = "changeit";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read(std::env::args().nth(1).unwrap())?;

    let policy = Pkcs12ImportPolicy::Strict;

    let keystore = KeyStore::from_pkcs12(&data, PASSWORD, policy)?;

    if let Some((alias, chain)) = keystore.private_key_chain() {
        println!(
            "Private key chain found, alias: {}, subject: {}",
            alias,
            chain.certs()[0].subject()
        );
    }

    Ok(())
}
```

## License

Licensed under MIT or Apache license ([LICENSE-MIT](https://opensource.org/licenses/MIT)
or [LICENSE-APACHE](https://opensource.org/licenses/Apache-2.0))
