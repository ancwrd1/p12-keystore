# PKCS#12 library written in pure Rust

## Overview

This project contains a simple to use high-level library to work with PKCS#12/PFX keystores, written in pure Rust,
 modeled after Java KeyStore API.

Features:

* Single- and multi-keychain PKCS#12
* Support for 'truststores' with only CA root certificates
* Modern and legacy encryption schemes
* Able to read and write Java-compatible keystores

Limitations:

* MD5-based encryption schemes are not supported
* Single password is used to encrypt both private keys and certificate data in one store
* Non-encrypted stores are not supported

[Documentation](https://docs.rs/p12-keystore)

## License

Licensed under MIT or Apache license ([LICENSE-MIT](https://opensource.org/licenses/MIT) or [LICENSE-APACHE](https://opensource.org/licenses/Apache-2.0))
