use crate::oid::{
    AES_128_CBC_KEY_OID, AES_192_CBC_KEY_OID, AES_256_CBC_KEY_OID, AES_GROUP_KEY_OID, BLOWFISH_KEY_OID,
    CAMELIA_KEY_OID, DES_CBC_KEY_OID, DES_EDE3_CBC_KEY_OID, HMAC_SHA1_KEY_OID, HMAC_SHA224_KEY_OID,
    HMAC_SHA256_KEY_OID, HMAC_SHA384_KEY_OID, HMAC_SHA512_KEY_OID, RC2_CBC_KEY_OID, RC4_KEY_OID,
};
use cms::cert::x509::spki::ObjectIdentifier;
use rand::rand_core::OsError;
use rand::rngs::OsRng;
use rand::TryRngCore;
use std::fmt;
use std::time::{Duration, UNIX_EPOCH};

#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    pub(crate) key_type: SecretKeyType,
    pub(crate) key: Vec<u8>,
    pub(crate) local_key_id: Vec<u8>,
}

impl Secret {
    /// Get private key data
    pub fn get_key(&self) -> &[u8] {
        &self.key
    }

    pub fn get_key_type(&self) -> SecretKeyType {
        self.key_type
    }

    pub fn get_local_key_id(&self) -> Vec<u8> {
        self.local_key_id.clone()
    }

    pub fn builder(key_type: SecretKeyType) -> SecretBuilder {
        SecretBuilder::new(key_type)
    }

    pub fn get_key_len(&self) -> usize {
        self.key.len()
    }
}

pub struct SecretBuilder {
    key_type: SecretKeyType,
    key: Option<Vec<u8>>,
    local_key_id: Option<Vec<u8>>,
    key_len: Option<usize>,
}

impl SecretBuilder {
    pub fn new(key_type: SecretKeyType) -> Self {
        let key_len = key_type.default_len();
        SecretBuilder {
            key_type,
            key: None,
            local_key_id: None,
            key_len,
        }
    }

    pub fn with_lenght(&mut self, len: usize) -> &mut Self {
        self.key_len = Some(len);
        self
    }

    pub fn with_key(&mut self, key: Vec<u8>) -> &mut Self {
        self.key_len = Some(key.len());
        self.key = Some(key);
        self
    }

    pub fn with_local_key_id(&mut self, local_key_id: Vec<u8>) -> &mut Self {
        self.local_key_id = Some(local_key_id);
        self
    }

    pub fn build(&mut self) -> Result<Secret, SecretKeyBuilderError> {
        if self.local_key_id.is_none() {
            let key_id_rng = OsRng.try_next_u32();

            match key_id_rng {
                Ok(key_id) => {
                    let ts = UNIX_EPOCH.elapsed().unwrap_or(Duration::from_secs(0)).as_millis();
                    self.local_key_id = Some(format!("{:0}:{:0}", ts, key_id).as_bytes().to_vec());
                }
                Err(e) => return Err(SecretKeyBuilderError::RandomGenerationError(e)),
            }
        }

        if self.key.is_none() {
            if let Some(key_len) = self.key_len {
                let mut key = vec![0u8; key_len];
                if let Err(e) = OsRng.try_fill_bytes(&mut key) {
                    return Err(SecretKeyBuilderError::RandomGenerationError(e));
                }
                self.key = Some(key);
            } else {
                return Err(SecretKeyBuilderError::MissingKeyLength);
            }
        }

        Ok(Secret {
            key_type: self.key_type,
            key: self.key.clone().unwrap(),
            local_key_id: self.local_key_id.clone().unwrap(),
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum SecretKeyBuilderError {
    MissingKeyLength,
    RandomGenerationError(OsError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKeyType {
    AES,
    AES128Cbc,
    AES192Cbc,
    AES256Cbc,
    DesCbc,
    DesEde3Cbc,
    Blowfish,
    Rc2Cbc,
    Rc4,
    Camelia,
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    Unknown(ObjectIdentifier),
}

impl SecretKeyType {
    pub fn from_oid(oid: &ObjectIdentifier) -> Self {
        match *oid {
            o if o == AES_GROUP_KEY_OID => SecretKeyType::AES,
            o if o == AES_128_CBC_KEY_OID => SecretKeyType::AES128Cbc,
            o if o == AES_192_CBC_KEY_OID => SecretKeyType::AES192Cbc,
            o if o == AES_256_CBC_KEY_OID => SecretKeyType::AES256Cbc,
            o if o == DES_CBC_KEY_OID => SecretKeyType::DesCbc,
            o if o == DES_EDE3_CBC_KEY_OID => SecretKeyType::DesEde3Cbc,
            o if o == BLOWFISH_KEY_OID => SecretKeyType::Blowfish,
            o if o == RC2_CBC_KEY_OID => SecretKeyType::Rc2Cbc,
            o if o == RC4_KEY_OID => SecretKeyType::Rc4,
            o if o == CAMELIA_KEY_OID => SecretKeyType::Camelia,
            o if o == HMAC_SHA1_KEY_OID => SecretKeyType::HmacSha1,
            o if o == HMAC_SHA224_KEY_OID => SecretKeyType::HmacSha224,
            o if o == HMAC_SHA256_KEY_OID => SecretKeyType::HmacSha256,
            o if o == HMAC_SHA384_KEY_OID => SecretKeyType::HmacSha384,
            o if o == HMAC_SHA512_KEY_OID => SecretKeyType::HmacSha512,
            _ => SecretKeyType::Unknown(*oid),
        }
    }

    pub fn to_oid(&self) -> ObjectIdentifier {
        match self {
            SecretKeyType::AES => AES_GROUP_KEY_OID,
            SecretKeyType::AES128Cbc => AES_128_CBC_KEY_OID,
            SecretKeyType::AES192Cbc => AES_192_CBC_KEY_OID,
            SecretKeyType::AES256Cbc => AES_256_CBC_KEY_OID,
            SecretKeyType::DesCbc => DES_CBC_KEY_OID,
            SecretKeyType::DesEde3Cbc => DES_EDE3_CBC_KEY_OID,
            SecretKeyType::Blowfish => BLOWFISH_KEY_OID,
            SecretKeyType::Rc2Cbc => RC2_CBC_KEY_OID,
            SecretKeyType::Rc4 => RC4_KEY_OID,
            SecretKeyType::Camelia => CAMELIA_KEY_OID,
            SecretKeyType::HmacSha1 => HMAC_SHA1_KEY_OID,
            SecretKeyType::HmacSha224 => HMAC_SHA224_KEY_OID,
            SecretKeyType::HmacSha256 => HMAC_SHA256_KEY_OID,
            SecretKeyType::HmacSha384 => HMAC_SHA384_KEY_OID,
            SecretKeyType::HmacSha512 => HMAC_SHA512_KEY_OID,
            SecretKeyType::Unknown(oid) => *oid,
        }
    }

    /// returns default key length in bytes
    pub(crate) fn default_len(&self) -> Option<usize> {
        match self {
            SecretKeyType::AES128Cbc => Some(16),
            SecretKeyType::AES192Cbc => Some(192 / 8),
            SecretKeyType::AES256Cbc => Some(256 / 8),
            SecretKeyType::HmacSha1 | SecretKeyType::HmacSha224 => Some(512 / 8),
            SecretKeyType::HmacSha256 | SecretKeyType::HmacSha384 | SecretKeyType::HmacSha512 => Some(1024 / 8),
            _ => None,
        }
    }

    pub fn from_oid_str(oid_str: &str) -> Self {
        SecretKeyType::from_oid(&ObjectIdentifier::new_unwrap(oid_str))
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKeyChain")
            .field("algorithm_oid", &self.key_type)
            .field("key", &"<KEY>")
            .field("local_key_id", &hex::encode(&self.local_key_id))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::oid::*;
    use crate::secret::{Secret, SecretKeyBuilderError, SecretKeyType};
    use der::oid::ObjectIdentifier;

    #[test]
    fn test_from_oid_str() {
        assert_eq!(
            SecretKeyType::AES,
            SecretKeyType::from_oid_str(&AES_GROUP_KEY_OID.to_string())
        );
        assert_eq!(
            SecretKeyType::AES128Cbc,
            SecretKeyType::from_oid_str(&AES_128_CBC_KEY_OID.to_string())
        );
        assert_eq!(
            SecretKeyType::AES192Cbc,
            SecretKeyType::from_oid_str(&AES_192_CBC_KEY_OID.to_string())
        );
        assert_eq!(
            SecretKeyType::AES256Cbc,
            SecretKeyType::from_oid_str(&AES_256_CBC_KEY_OID.to_string())
        );
        assert_eq!(
            SecretKeyType::DesCbc,
            SecretKeyType::from_oid_str(&DES_CBC_KEY_OID.to_string())
        );
        assert_eq!(
            SecretKeyType::DesEde3Cbc,
            SecretKeyType::from_oid_str(&DES_EDE3_CBC_KEY_OID.to_string())
        );
        assert_eq!(
            SecretKeyType::Blowfish,
            SecretKeyType::from_oid_str(&BLOWFISH_KEY_OID.to_string())
        );
        assert_eq!(
            SecretKeyType::Rc2Cbc,
            SecretKeyType::from_oid_str(&RC2_CBC_KEY_OID.to_string())
        );
        assert_eq!(
            SecretKeyType::Rc4,
            SecretKeyType::from_oid_str(&RC4_KEY_OID.to_string())
        );
        assert_eq!(
            SecretKeyType::Camelia,
            SecretKeyType::from_oid_str(&CAMELIA_KEY_OID.to_string())
        );
        assert_eq!(
            SecretKeyType::HmacSha1,
            SecretKeyType::from_oid_str(&HMAC_SHA1_KEY_OID.to_string())
        );
        assert_eq!(
            SecretKeyType::HmacSha224,
            SecretKeyType::from_oid_str(&HMAC_SHA224_KEY_OID.to_string())
        );
        assert_eq!(
            SecretKeyType::HmacSha256,
            SecretKeyType::from_oid_str(&HMAC_SHA256_KEY_OID.to_string())
        );
        assert_eq!(
            SecretKeyType::HmacSha384,
            SecretKeyType::from_oid_str(&HMAC_SHA384_KEY_OID.to_string())
        );
        assert_eq!(
            SecretKeyType::HmacSha512,
            SecretKeyType::from_oid_str(&HMAC_SHA512_KEY_OID.to_string())
        );

        // Unknown OID check (any OID not in the mapping)
        let dummy_oid = ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7");
        assert_eq!(
            SecretKeyType::Unknown(dummy_oid),
            SecretKeyType::from_oid_str("1.2.3.4.5.6.7")
        );
    }

    #[test]
    fn test_from_oid() {
        assert_eq!(SecretKeyType::AES, SecretKeyType::from_oid(&AES_GROUP_KEY_OID));
        assert_eq!(SecretKeyType::AES128Cbc, SecretKeyType::from_oid(&AES_128_CBC_KEY_OID));
        assert_eq!(SecretKeyType::AES192Cbc, SecretKeyType::from_oid(&AES_192_CBC_KEY_OID));
        assert_eq!(SecretKeyType::AES256Cbc, SecretKeyType::from_oid(&AES_256_CBC_KEY_OID));
        assert_eq!(SecretKeyType::DesCbc, SecretKeyType::from_oid(&DES_CBC_KEY_OID));
        assert_eq!(
            SecretKeyType::DesEde3Cbc,
            SecretKeyType::from_oid(&DES_EDE3_CBC_KEY_OID)
        );
        assert_eq!(SecretKeyType::Blowfish, SecretKeyType::from_oid(&BLOWFISH_KEY_OID));
        assert_eq!(SecretKeyType::Rc2Cbc, SecretKeyType::from_oid(&RC2_CBC_KEY_OID));
        assert_eq!(SecretKeyType::Rc4, SecretKeyType::from_oid(&RC4_KEY_OID));
        assert_eq!(SecretKeyType::Camelia, SecretKeyType::from_oid(&CAMELIA_KEY_OID));
        assert_eq!(SecretKeyType::HmacSha1, SecretKeyType::from_oid(&HMAC_SHA1_KEY_OID));
        assert_eq!(SecretKeyType::HmacSha224, SecretKeyType::from_oid(&HMAC_SHA224_KEY_OID));
        assert_eq!(SecretKeyType::HmacSha256, SecretKeyType::from_oid(&HMAC_SHA256_KEY_OID));
        assert_eq!(SecretKeyType::HmacSha384, SecretKeyType::from_oid(&HMAC_SHA384_KEY_OID));
        assert_eq!(SecretKeyType::HmacSha512, SecretKeyType::from_oid(&HMAC_SHA512_KEY_OID));

        // Unknown OID check (any OID not in the mapping)
        let dummy_oid = ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7");
        assert_eq!(SecretKeyType::Unknown(dummy_oid), SecretKeyType::from_oid(&dummy_oid));
    }

    #[test]
    fn test_getters_and_setters() {
        // Setup initial values
        let initial_key = vec![1, 2, 3];
        let initial_key_type = SecretKeyType::AES128Cbc;
        let initial_local_key_id = vec![10, 20, 30];

        let mut secret = Secret {
            key: initial_key.clone(),
            key_type: initial_key_type,
            local_key_id: initial_local_key_id.clone(),
        };

        // Test getters for initial values
        assert_eq!(secret.get_key(), &initial_key[..]);
        assert_eq!(secret.get_key_type(), initial_key_type);
        assert_eq!(secret.get_local_key_id(), initial_local_key_id);
    }

    #[test]
    fn test_secret_builder() {
        let secret = Secret::builder(SecretKeyType::AES256Cbc).build();
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert_eq!(secret.get_key_type(), SecretKeyType::AES256Cbc);
            assert_eq!(secret.get_key_len(), 32);
        }
    }

    #[test]
    fn test_secret_builder_with_aes128_generic() {
        let secret = Secret::builder(SecretKeyType::AES).with_lenght(16).build();
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert_eq!(secret.get_key_type(), SecretKeyType::AES);
            assert_eq!(secret.get_key_len(), 16);
        }
    }

    #[test]
    fn test_secret_builder_with_aes192() {
        let secret = Secret::builder(SecretKeyType::AES192Cbc).build();
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert_eq!(secret.get_key_type(), SecretKeyType::AES192Cbc);
            assert_eq!(secret.get_key_len(), 24);
        }
    }

    #[test]
    fn test_secret_builder_with_missing_len() {
        let secret = Secret::builder(SecretKeyType::AES).build();
        assert!(secret.is_err());
        if let Err(e) = secret {
            assert_eq!(e, SecretKeyBuilderError::MissingKeyLength);
        }
    }

    #[test]
    fn test_secret_builder_with_val() {
        let key_val = vec![[17u8; 32]].as_flattened().to_vec();
        let secret = Secret::builder(SecretKeyType::AES).with_key(key_val.clone()).build();
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert_eq!(secret.get_key_type(), SecretKeyType::AES);
            assert_eq!(secret.get_key_len(), 32);
            assert_eq!(key_val, secret.get_key());
        }
    }

    #[test]
    fn test_secret_builder_with_val_n_id() {
        let key_val = vec![[17u8; 32]].as_flattened().to_vec();
        let key_id_val = vec![[0u8; 20]].as_flattened().to_vec();
        let secret = Secret::builder(SecretKeyType::AES256Cbc)
            .with_key(key_val.clone())
            .with_local_key_id(key_id_val.clone())
            .build();
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert_eq!(secret.get_key_type(), SecretKeyType::AES256Cbc);
            assert_eq!(secret.get_key_len(), 32);
            assert_eq!(key_val, secret.get_key());
            assert_eq!(key_id_val, secret.get_local_key_id());
        }
    }
}
