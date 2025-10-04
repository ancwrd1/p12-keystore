//!
//! [Error] enum definition
//!
use std::io;

use hmac::digest::MacError;
use x509_parser::error::X509Error;

/// Possible errors for keystore operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error(transparent)]
    DerError(#[from] der::Error),

    #[error("Invalid PFX version")]
    InvalidVersion,

    #[error("Unsupported ContentType")]
    UnsupportedContentType,

    #[error("Unsupported certiticate type")]
    UnsupportedCertificateType,

    #[error(transparent)]
    X509Error(#[from] x509_parser::nom::Err<X509Error>),

    #[error("Invalid length")]
    InvalidLength,

    #[error("Unpad error")]
    UnpadError,

    #[error("Invalid parameters")]
    InvalidParameters,

    #[error("Invalid data")]
    InvalidData,

    #[error("Unsupported encryption scheme")]
    UnsupportedEncryptionScheme,

    #[error("Unsupported MAC algorithm")]
    UnsupportedMacAlgorithm,

    #[error("{0}")]
    Pkcs5Error(String),

    #[error(transparent)]
    MacError(#[from] MacError),

    #[error("Invalid private key")]
    InvalidPrivateKey,
}
