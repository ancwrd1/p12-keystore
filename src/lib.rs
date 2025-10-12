//!
//! A convenient high-level library to work with PKCS#12/PFX keystores, written in pure Rust,
//! modeled after Java KeyStore API.
//!
//! This crate consists of a [KeyStore] struct which provides a set of functions to read and write PKCS#12 files
//! and their contents. It supports single- or multi-keychain keystores and also so called 'truststores'
//! (keystores with only root certificates and without private keys).
//!
//! Each entry in the keystore is accessed by 'alias', which is a friendly name chosen when creating it.
//!
//! All certificates must be encoded in X.509 format. Private keys must be encoded in PKCS#8.
//!
//! Each private key contains a key material, a local key ID (unique byte or string sequence) and a list of
//! certificates organized into chain. The first in the chain must be the entity certificate associated with
//! the private key. The last must be the CA root certificate, with any intermediates in between.
//!
//! Supported encryption schemes:
//!
//! * [EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc] - legacy encryption to support the existing stores
//! * [EncryptionAlgorithm::PbeWithShaAnd40BitRc4Cbc] - legacy encryption to support the existing stores
//! * [EncryptionAlgorithm::PbeWithHmacSha256AndAes256] - the default encryption which should be used for new keystores
//!
//! Supported MAC algorithms: [MacAlgorithm::HmacSha1], [MacAlgorithm::HmacSha256]
//!

mod cert;
mod codec;
pub mod error;
mod keychain;
mod keystore;
mod oid;
#[cfg(feature = "pbes1")]
mod pbes1;
pub mod secret;

pub use rand;

/// Result type for keystore operations
pub type Result<T> = std::result::Result<T, error::Error>;

pub use cert::Certificate;
pub use keychain::{LocalKeyId, PrivateKeyChain};
pub use keystore::{EncryptionAlgorithm, KeyStore, KeyStoreEntry, MacAlgorithm, Pkcs12Writer};
