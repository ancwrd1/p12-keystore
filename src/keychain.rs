use std::fmt;

use der::oid::ObjectIdentifier;
use pkcs8::PrivateKeyInfoRef;

use crate::{Result, cert::Certificate, error::Error};

/// Wrapper for a local key id
#[derive(Clone, PartialEq, Eq)]
pub struct LocalKeyId(pub Vec<u8>);

impl From<Vec<u8>> for LocalKeyId {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for LocalKeyId {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl From<&str> for LocalKeyId {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }
}

impl From<String> for LocalKeyId {
    fn from(value: String) -> Self {
        Self(value.into())
    }
}

impl AsRef<[u8]> for LocalKeyId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for LocalKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LocalKeyId").field(&hex::encode(&self.0)).finish()
    }
}

/// PKCS#8 private key wrapper
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKey {
    pub(crate) data: Vec<u8>,
    pub(crate) oid: ObjectIdentifier,
}

impl PrivateKey {
    /// Parses a PKCS#8 private key encoded in DER format and constructs a new instance of the struct.
    pub fn from_der(data: &[u8]) -> Result<Self> {
        let info: PrivateKeyInfoRef = data.try_into().map_err(|_| Error::InvalidPrivateKey)?;
        Ok(Self {
            data: data.to_vec(),
            oid: info.algorithm.oid,
        })
    }

    /// Returns a reference to the private key data in PKCS#8 DER-encoded format.
    pub fn as_der(&self) -> &[u8] {
        &self.data
    }

    /// Returns an ObjectIdentifier of the key algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        self.oid
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("data", &"<PKCS#8>")
            .field("oid", &self.oid)
            .finish()
    }
}

/// PrivateKeyChain represents a private key and a certificate chain
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKeyChain {
    pub(crate) key: PrivateKey,
    pub(crate) local_key_id: LocalKeyId,
    pub(crate) certs: Vec<Certificate>,
}

impl PrivateKeyChain {
    /// Creates a new keychain with a given key id, private key and a list of certificates.
    /// The leaf (entity) certificate must be the first in the list, and the root certificate must be the last.
    pub fn new<K, I>(local_key_id: K, key: PrivateKey, certs: I) -> Self
    where
        K: Into<LocalKeyId>,
        I: IntoIterator<Item = Certificate>,
    {
        Self {
            key,
            local_key_id: local_key_id.into(),
            certs: certs.into_iter().collect(),
        }
    }

    /// Get a private key
    pub fn key(&self) -> &PrivateKey {
        &self.key
    }

    /// Get certificates
    pub fn certs(&self) -> &[Certificate] {
        &self.certs
    }

    /// Get local key id
    pub fn local_key_id(&self) -> &LocalKeyId {
        &self.local_key_id
    }
}

impl fmt::Debug for PrivateKeyChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKeyChain")
            .field("key", &self.key)
            .field("certs", &self.certs)
            .field("local_key_id", &hex::encode(&self.local_key_id))
            .finish()
    }
}
