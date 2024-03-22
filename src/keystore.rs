use std::{
    collections::{btree_map::Iter, BTreeMap},
    fmt,
};

use cms::content_info::ContentInfo;
use der::oid::ObjectIdentifier;
use der::{asn1::OctetString, Any, Decode, Encode};
use pkcs12::{
    authenticated_safe::AuthenticatedSafe,
    pfx::{Pfx, Version},
};

use crate::{codec, error::Error, oid, Result};

/// X.509 certificate wrapper
#[derive(Clone, PartialEq, Eq)]
pub struct Certificate {
    pub(crate) data: Vec<u8>,
    pub(crate) subject: String,
    pub(crate) issuer: String,
}

impl Certificate {
    /// Create certificate from DER encoding
    pub fn from_der(der: &[u8]) -> crate::Result<Self> {
        let (_, cert) = x509_parser::parse_x509_certificate(der)?;
        Ok(Self {
            data: der.to_vec(),
            subject: cert.subject.to_string(),
            issuer: cert.issuer.to_string(),
        })
    }

    /// Get certificate subject
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Get certificate issuer
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Get certificate data in DER encoding
    pub fn as_der(&self) -> &[u8] {
        &self.data
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("data", &"<CERT>")
            .field("subject", &self.subject)
            .field("issuer", &self.issuer)
            .finish()
    }
}

/// PrivateKeyChain represents a private key and a certificate chain
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKeyChain {
    pub(crate) key: Vec<u8>,
    pub(crate) local_key_id: Vec<u8>,
    pub(crate) chain: Vec<Certificate>,
}

impl PrivateKeyChain {
    /// Create new keychain with a given key data, key id and a list of certificates.
    /// The leaf (entity) certificate must be the first in the list, and the root certificate must be the last.
    pub fn new<K, D, I>(key: K, local_key_id: D, chain: I) -> Self
    where
        K: AsRef<[u8]>,
        D: AsRef<[u8]>,
        I: IntoIterator<Item = Certificate>,
    {
        Self {
            key: key.as_ref().to_owned(),
            local_key_id: local_key_id.as_ref().to_owned(),
            chain: chain.into_iter().collect(),
        }
    }

    /// Get private key data
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Get a slice of certificates
    pub fn chain(&self) -> &[Certificate] {
        &self.chain
    }

    /// Get local key id
    pub fn local_key_id(&self) -> &[u8] {
        &self.local_key_id
    }
}

impl fmt::Debug for PrivateKeyChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKeyChain")
            .field("key", &"<KEY>")
            .field("chain", &self.chain)
            .field("local_key_id", &hex::encode(&self.local_key_id))
            .finish()
    }
}

/// KeyStoreEntry represents one entry in the keystore
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStoreEntry {
    PrivateKeyChain(PrivateKeyChain),
    Certificate(Certificate),
}

/// Keystore entries iterator
pub struct Entries<'a> {
    iter: Iter<'a, String, KeyStoreEntry>,
}

impl<'a> Iterator for Entries<'a> {
    type Item = (&'a String, &'a KeyStoreEntry);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

/// KeyStore holds a dictionary of [KeyStoreEntry] instances indexed by aliases (names)
#[derive(Debug, Clone)]
pub struct KeyStore {
    entries: BTreeMap<String, KeyStoreEntry>,
}

impl KeyStore {
    /// Create new empty keystore
    pub fn new() -> Self {
        Self {
            entries: Default::default(),
        }
    }

    /// Parse keystore from PKCS#12 data
    pub fn from_pkcs12(data: &[u8], password: &str) -> crate::Result<Self> {
        let pfx = Pfx::from_der(data)?;

        if pfx.version != Version::V3 {
            return Err(Error::InvalidVersion);
        }

        if let Some(mac_data) = pfx.mac_data {
            codec::verify_mac(&mac_data, password, pfx.auth_safe.content.value())?;
        }

        let safes: AuthenticatedSafe = if pfx.auth_safe.content_type == oid::CONTENT_TYPE_DATA_OID {
            AuthenticatedSafe::from_der(
                &OctetString::from_der(&pfx.auth_safe.content.to_der()?)?.into_bytes(),
            )?
        } else {
            return Err(Error::UnsupportedContentType);
        };

        let mut keystore = Self::new();

        let mut keys = Vec::new();
        let mut certs = Vec::new();

        for safe in safes.into_iter() {
            let (safe_keys, safe_certs) = codec::parse_auth_safe(&safe, password)?;
            keys.extend(safe_keys);
            certs.extend(safe_certs);
        }

        let find_cert_by_key = |key: &[u8]| {
            certs
                .iter()
                .find(|c| c.1.as_ref().is_some_and(|k| k.as_slice() == key))
        };

        let find_issuer = |issuer: &str| certs.iter().find(|c| c.3.subject == issuer && !c.2);

        for (alias, key) in keys {
            if let Some(mut entry) = find_cert_by_key(&key.local_key_id) {
                let alias = alias.as_deref().unwrap_or_else(|| entry.3.subject.as_ref());

                let mut key_chain = PrivateKeyChain {
                    key: key.key,
                    local_key_id: key.local_key_id,
                    chain: vec![entry.3.clone()],
                };

                while let Some(issuer) = find_issuer(&entry.3.issuer) {
                    key_chain.chain.push(issuer.3.clone());
                    if issuer.3.issuer == issuer.3.subject {
                        break;
                    }
                    entry = issuer;
                }
                keystore.add_entry(alias, KeyStoreEntry::PrivateKeyChain(key_chain));
            }
        }

        for (friendly_name, local_key_id, trusted, cert) in certs {
            if local_key_id.is_none() && trusted {
                let alias = friendly_name
                    .clone()
                    .unwrap_or_else(|| cert.subject.clone());
                keystore.add_entry(&alias, KeyStoreEntry::Certificate(cert));
            }
        }

        Ok(keystore)
    }

    /// Create keystore writer with a given password to use for data encryption
    pub fn writer<'a, 'b>(&'a self, password: &'b str) -> Pkcs12Writer<'a, 'b> {
        // default values are taken from JVM java.security config file
        Pkcs12Writer {
            keystore: self,
            password,
            encryption_algorithm: EncryptionAlgorithm::PbeWithHmacSha256AndAes256,
            encryption_iterations: 10000,
            mac_algorithm: MacAlgorithm::HmacSha256,
            mac_iterations: 10000,
        }
    }

    /// Get entries iterator
    pub fn entries(&self) -> Entries {
        let iter = self.entries.iter();
        Entries { iter }
    }

    /// Get an entry for a given alias
    pub fn entry(&self, alias: &str) -> Option<&KeyStoreEntry> {
        self.entries.get(alias)
    }

    /// Get entries count in the keystore
    pub fn entries_count(&self) -> usize {
        self.entries.len()
    }

    /// Add new entry to the keystore
    pub fn add_entry(&mut self, alias: &str, entry: KeyStoreEntry) {
        self.entries.insert(alias.to_owned(), entry);
    }

    /// Delete entry from the keystore
    pub fn delete_entry(&mut self, alias: &str) -> Option<KeyStoreEntry> {
        self.entries.remove(alias)
    }

    /// Rename entry in the keystore. If an entry with new alias already exists it will be replaced
    pub fn rename_entry(&mut self, old_alias: &str, new_alias: &str) -> Option<&KeyStoreEntry> {
        if let Some(old) = self.entries.remove(old_alias) {
            self.entries.insert(new_alias.to_owned(), old);
            self.entry(new_alias)
        } else {
            None
        }
    }

    /// Get the first private keychain
    pub fn private_key_chain(&self) -> Option<(&str, &PrivateKeyChain)> {
        self.entries().find_map(|(alias, entry)| match entry {
            KeyStoreEntry::PrivateKeyChain(chain) => Some((alias.as_str(), chain)),
            KeyStoreEntry::Certificate(_) => None,
        })
    }
}

/// Encryption algorithm to use when creating the PKCS#12 file
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum EncryptionAlgorithm {
    PbeWithHmacSha256AndAes256,
    PbeWithShaAnd40BitRc4Cbc,
    PbeWithShaAnd3KeyTripleDesCbc,
}

impl EncryptionAlgorithm {
    pub(crate) fn to_oid(&self) -> ObjectIdentifier {
        match self {
            EncryptionAlgorithm::PbeWithHmacSha256AndAes256 => oid::PBES2_OID,
            EncryptionAlgorithm::PbeWithShaAnd40BitRc4Cbc => {
                oid::PBE_WITH_SHA_AND_40BIT_RC2_CBC_OID
            }
            EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc => {
                oid::PBE_WITH_SHA_AND3_KEY_TRIPLE_DES_CBC_OID
            }
        }
    }
}

/// MAC algorithm to use when creating the PKCS#12 file
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum MacAlgorithm {
    HmacSha1,
    HmacSha256,
}

/// PKCS#12 writer
pub struct Pkcs12Writer<'a, 'b> {
    keystore: &'a KeyStore,
    password: &'b str,
    encryption_algorithm: EncryptionAlgorithm,
    encryption_iterations: u64,
    mac_algorithm: MacAlgorithm,
    mac_iterations: u64,
}

impl<'a, 'b> Pkcs12Writer<'a, 'b> {
    /// Set encryption algorithm. Default is [EncryptionAlgorithm::PbeWithHmacSha256AndAes256]
    pub fn encryption_algorithm(mut self, algorithm: EncryptionAlgorithm) -> Self {
        self.encryption_algorithm = algorithm;
        self
    }

    /// Set encryption iterations. Default is 10000
    pub fn encryption_iterations(mut self, iterations: u64) -> Self {
        self.encryption_iterations = iterations;
        self
    }

    /// Set MAC algorithm. Default is [MacAlgorithm::HmacSha256]
    pub fn mac_algorithm(mut self, algorithm: MacAlgorithm) -> Self {
        self.mac_algorithm = algorithm;
        self
    }

    /// Set MAC iterations. Default is 10000
    pub fn mac_iterations(mut self, iterations: u64) -> Self {
        self.mac_iterations = iterations;
        self
    }

    /// Write keystore into PKCS#12 format
    pub fn write(self) -> Result<Vec<u8>> {
        let mut cert_bags = Vec::new();

        let certs = self
            .keystore
            .entries
            .iter()
            .filter_map(|(alias, entry)| match entry {
                KeyStoreEntry::PrivateKeyChain(_) => None,
                KeyStoreEntry::Certificate(cert) => Some((alias, cert)),
            });

        for (alias, cert) in certs {
            cert_bags.push(codec::certificate_to_safe_bag(cert, alias, None, true)?);
        }

        let chain_certs = self
            .keystore
            .entries
            .iter()
            .filter_map(|(_, entry)| match entry {
                KeyStoreEntry::PrivateKeyChain(chain) => {
                    Some(chain.chain.iter().enumerate().map(|(i, c)| {
                        (
                            if i == 0 {
                                Some(chain.local_key_id.as_slice())
                            } else {
                                None
                            },
                            c,
                        )
                    }))
                }
                KeyStoreEntry::Certificate(_) => None,
            })
            .flatten();

        for (local_key_id, cert) in chain_certs {
            cert_bags.push(codec::certificate_to_safe_bag(
                cert,
                &cert.subject,
                local_key_id,
                false,
            )?);
        }

        let certs_safe = codec::cert_bags_to_auth_safe(
            cert_bags,
            self.encryption_algorithm,
            self.encryption_iterations,
            self.password,
        )?;

        let private_keys = self
            .keystore
            .entries
            .iter()
            .filter_map(|(alias, entry)| match entry {
                KeyStoreEntry::PrivateKeyChain(chain) => Some((alias, chain)),
                KeyStoreEntry::Certificate(_) => None,
            });

        let mut key_bags = Vec::new();

        for (alias, chain) in private_keys {
            key_bags.push(codec::private_key_to_safe_bag(
                chain,
                alias,
                self.encryption_algorithm,
                self.encryption_iterations,
                self.password,
            )?);
        }

        let keys_safe = codec::key_bags_to_auth_safe(key_bags)?;

        let safes = OctetString::new(vec![certs_safe, keys_safe].to_der()?)?;

        let auth_safe = ContentInfo {
            content_type: oid::CONTENT_TYPE_DATA_OID,
            content: Any::from_der(&safes.to_der()?)?,
        };

        let mac_data = codec::compute_mac(
            auth_safe.content.value(),
            self.mac_algorithm,
            self.mac_iterations,
            self.password,
        )?;

        let pfx = Pfx {
            version: Version::V3,
            auth_safe,
            mac_data: Some(mac_data),
        };

        Ok(pfx.to_der()?)
    }
}
