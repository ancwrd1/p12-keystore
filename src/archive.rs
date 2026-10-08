use der::{Decode, Encode, asn1::OctetString};
use pkcs12::{
    AuthenticatedSafe,
    pfx::{Pfx, Version},
};

use crate::{Certificate, LocalKeyId, PrivateKey, Result, codec, error::Error, oid, secret::Secret};

/// A decoded private key bag, before certificate linking or alias assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKeyBag {
    /// Optional friendly name from the bag attributes.
    pub friendly_name: Option<String>,
    /// Optional local key ID from the bag attributes.
    pub local_key_id: Option<LocalKeyId>,
    /// The decrypted PKCS#8 private key.
    pub key: PrivateKey,
}

/// A decoded X.509 certificate bag, before chain construction or filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateBag {
    /// Optional friendly name from the bag attributes.
    pub friendly_name: Option<String>,
    /// Optional local key ID from the bag attributes.
    pub local_key_id: Option<Vec<u8>>,
    /// Whether the bag has the Java trusted certificate attribute.
    pub trusted: bool,
    /// The X.509 certificate.
    pub cert: Certificate,
}

/// A decoded secret key bag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretBag {
    /// Optional friendly name from the bag attributes.
    pub friendly_name: Option<String>,
    /// The decrypted secret key.
    pub key: Secret,
}

/// Supported decoded PKCS#12 bags before keystore import policy is applied.
///
/// Each collection retains bag order and duplicates. Friendly names are
/// metadata rather than map keys, so name collisions do not overwrite bags.
/// This allows callers to implement their own key matching, chain validation,
/// and handling of unrelated certificates. It does not verify certificate
/// signatures, validity periods, or whether a certificate matches a key.
///
/// As with [`crate::KeyStore`], unsupported bag types are ignored. Supported
/// private key bags are retained even without a local key ID.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pkcs12Archive {
    /// Decoded private key bags.
    pub keys: Vec<PrivateKeyBag>,
    /// Decoded certificate bags, including duplicates and unrelated bags.
    pub certs: Vec<CertificateBag>,
    /// Decoded secret key bags.
    pub secrets: Vec<SecretBag>,
}

impl Pkcs12Archive {
    /// Decode a PKCS#12 archive using `password`.
    ///
    /// Verifies the MAC when present and decrypts supported encrypted bags.
    /// No alias mapping, deduplication, certificate linking, or trust filtering
    /// is performed. MAC-less archives are accepted, as by [`crate::KeyStore`].
    pub fn from_pkcs12(data: &[u8], password: &str) -> Result<Self> {
        let pfx = Pfx::from_der(data)?;
        if pfx.version != Version::V3 {
            return Err(Error::InvalidVersion);
        }
        if let Some(mac_data) = pfx.mac_data {
            codec::verify_mac(&mac_data, password, pfx.auth_safe.content.value())?;
        }
        let safes: AuthenticatedSafe = if pfx.auth_safe.content_type == oid::CONTENT_TYPE_DATA_OID {
            AuthenticatedSafe::from_der(&OctetString::from_der(&pfx.auth_safe.content.to_der()?)?.into_bytes())?
        } else {
            return Err(Error::UnsupportedContentType);
        };
        let mut archive = Self::default();
        for safe in safes {
            let decoded = codec::parse_auth_safe(&safe, password)?;
            archive.keys.extend(decoded.keys);
            archive.certs.extend(decoded.certs);
            archive.secrets.extend(decoded.secrets);
        }
        Ok(archive)
    }
}
