use std::{fmt, str::FromStr, time::UNIX_EPOCH};

use der::oid::ObjectIdentifier;
use rand::{RngCore, TryRngCore, rngs::OsRng};

use crate::{LocalKeyId, oid};

/// Holds a secret key of a given type.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    pub(crate) key_type: SecretKeyType,
    pub(crate) key: Vec<u8>,
    pub(crate) local_key_id: LocalKeyId,
}

/// Implementation of the `Secret` methods.
impl Secret {
    /// Get key data
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Get the key type
    pub fn key_type(&self) -> SecretKeyType {
        self.key_type
    }

    /// gets the local_key_id
    pub fn local_key_id(&self) -> &LocalKeyId {
        &self.local_key_id
    }

    /// The builder to build a secret of a given type. If the type has no length assigned,
    /// it needs also a .with_length(N).
    /// # Example:
    /// ```
    /// use p12_keystore::secret::Secret;
    /// use p12_keystore::secret::SecretKeyType::Aes;
    /// let secret = Secret::builder(Aes).with_length(24).build();
    /// ```
    ///
    pub fn builder(key_type: SecretKeyType) -> SecretBuilder {
        SecretBuilder::new(key_type)
    }
}

/// The builder for secrets. It starts with a secret type. If the key type has a length associated,
/// then you do not need to set the length. You can overwrite the `local_key_id` and the `key` itself.
///
/// # Examples:
/// ```
/// use p12_keystore::secret::Secret;
/// use p12_keystore::secret::SecretKeyType::{Aes256Cbc, Aes};
///
/// // creates a generic AES secret with any length (128,192,256 bits)
/// let secret_aes = Secret::builder(Aes).with_length(24).build();
/// let secret_aes_256 = Secret::builder(Aes256Cbc).build();
///
/// // build with a given local_key_id
/// let local_key_id = vec![4,7,1,1];
/// let secret_aes = Secret::builder(Aes).with_length(32).with_local_key_id(local_key_id).build();
///
/// // build with a given key
/// let key = [0u8,16];
/// let secret_aes = Secret::builder(Aes).with_key(Vec::from(key)).build();
/// ```
pub struct SecretBuilder {
    key_type: SecretKeyType,
    key: Option<Vec<u8>>,
    local_key_id: Option<LocalKeyId>,
    key_len: Option<usize>,
    rng: Box<dyn RandomGenerator>,
}

/// Implementation for the SecretBuilder methods
impl SecretBuilder {
    /// Creates a new SecretBuilder with a given key type. If SecretKeyType has a length assigned,
    /// there is no need to set the key length
    pub fn new(key_type: SecretKeyType) -> Self {
        let key_len = key_type.default_len();
        SecretBuilder {
            key_type,
            key: None,
            local_key_id: None,
            key_len,
            rng: Box::new(OsRngRandomGenerator),
        }
    }

    /// Provides the key length in byes. This is only required if you do not use a SecretKeyType
    /// with a length assigned, or you do not provide a key value.
    pub fn with_length(&mut self, len: usize) -> &mut Self {
        self.key_len = Some(len);
        self
    }

    /// Preloads the key, if omitted, it will be generated using OsRng
    pub fn with_key(&mut self, key: Vec<u8>) -> &mut Self {
        self.key_len = Some(key.len());
        self.key = Some(key);
        self
    }

    /// Predefines the local_key_id. If omitted, it is generated based on timestamp and random.
    pub fn with_local_key_id<K>(&mut self, local_key_id: K) -> &mut Self
    where
        K: Into<LocalKeyId>,
    {
        self.local_key_id = Some(local_key_id.into());
        self
    }

    /// allows overwriting the default OsRng based `RandomGenerator` implementation
    /// # Examples:
    /// ```
    /// use rand::rngs::ThreadRng;
    /// use p12_keystore::secret::Secret;
    /// use p12_keystore::secret::SecretKeyType::Aes;
    ///
    /// let key = Secret::builder(Aes).with_length(32).with_rng(ThreadRng::default()).build();
    ///
    /// ```
    pub fn with_rng<R: RandomGenerator + 'static>(&mut self, rng: R) -> &mut Self {
        self.rng = Box::new(rng);
        self
    }

    /// builds the secret
    pub fn build(&mut self) -> Result<Secret, SecretKeyBuilderError> {
        if self.local_key_id.is_none() {
            let key_id_rng = self.rng.try_next_u32();

            match key_id_rng {
                Ok(key_id) => {
                    let ts = UNIX_EPOCH.elapsed().unwrap_or_default().as_millis();
                    self.local_key_id = Some(format!("{ts:0}:{key_id:0}").into());
                }
                Err(_) => return Err(SecretKeyBuilderError::RandomGenerationError),
            }
        }

        if self.key.is_none() {
            if let Some(key_len) = self.key_len {
                let mut key = vec![0u8; key_len];
                if self.rng.try_fill_bytes(&mut key).is_err() {
                    return Err(SecretKeyBuilderError::RandomGenerationError);
                }
                self.key = Some(key);
            } else {
                return Err(SecretKeyBuilderError::MissingKeyLength);
            }
        }

        if let (Some(key), Some(local_key_id)) = (&self.key, &self.local_key_id) {
            Ok(Secret {
                key_type: self.key_type,
                key: key.clone(),
                local_key_id: local_key_id.clone(),
            })
        } else {
            Err(SecretKeyBuilderError::MissingKeyOrLocalKeyId)
        }
    }
}
/// Implements a simplified random generator which can be used dynamically
pub trait RandomGenerator {
    /// returns a random u32
    fn try_next_u32(&mut self) -> Result<u32, SecretKeyBuilderError>;

    /// fills a byte buffer with random
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), SecretKeyBuilderError>;
}

/// Implements random generator for all RngCore implementations
impl<R: RngCore + ?Sized> RandomGenerator for R {
    /// returns a random u32
    fn try_next_u32(&mut self) -> Result<u32, SecretKeyBuilderError> {
        Ok(R::next_u32(self))
    }
    /// fills a byte buffer with random
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), SecretKeyBuilderError> {
        R::fill_bytes(self, buf);
        Ok(())
    }
}

/// OsRng based RandomGenerator
#[derive(Default)]
pub struct OsRngRandomGenerator;

/// Implementation for OsRng
impl RandomGenerator for OsRngRandomGenerator {
    fn try_next_u32(&mut self) -> Result<u32, SecretKeyBuilderError> {
        match OsRng.try_next_u32() {
            Ok(rnd) => Ok(rnd),
            Err(_) => Err(SecretKeyBuilderError::RandomGenerationError),
        }
    }

    /// fills a byte buffer with random
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), SecretKeyBuilderError> {
        match OsRng.try_fill_bytes(buf) {
            Ok(_) => Ok(()),
            Err(_) => Err(SecretKeyBuilderError::RandomGenerationError),
        }
    }
}

/// Error, which can be returned by the `SecretBuilder`
#[derive(Debug, PartialEq)]
pub enum SecretKeyBuilderError {
    MissingKeyLength,
    MissingKeyOrLocalKeyId,
    RandomGenerationError,
}

/// Available types of secrets. If the type is unknown, use `Unknown(<oid>)`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKeyType {
    Aes,
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
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

/// Implements important conversions for `SecretKeyType`
///
impl SecretKeyType {
    /// Builds a `SecretKeyType` from an `ObjectIdentifier`
    pub fn from_oid(oid: &ObjectIdentifier) -> Self {
        match *oid {
            oid::AES_GROUP_KEY_OID => SecretKeyType::Aes,
            oid::AES_128_CBC_KEY_OID => SecretKeyType::Aes128Cbc,
            oid::AES_192_CBC_KEY_OID => SecretKeyType::Aes192Cbc,
            oid::AES_256_CBC_KEY_OID => SecretKeyType::Aes256Cbc,
            oid::DES_CBC_KEY_OID => SecretKeyType::DesCbc,
            oid::DES_EDE3_CBC_KEY_OID => SecretKeyType::DesEde3Cbc,
            oid::BLOWFISH_KEY_OID => SecretKeyType::Blowfish,
            oid::RC2_CBC_KEY_OID => SecretKeyType::Rc2Cbc,
            oid::RC4_KEY_OID => SecretKeyType::Rc4,
            oid::CAMELIA_KEY_OID => SecretKeyType::Camelia,
            oid::HMAC_SHA1_KEY_OID => SecretKeyType::HmacSha1,
            oid::HMAC_SHA224_KEY_OID => SecretKeyType::HmacSha224,
            oid::HMAC_SHA256_KEY_OID => SecretKeyType::HmacSha256,
            oid::HMAC_SHA384_KEY_OID => SecretKeyType::HmacSha384,
            oid::HMAC_SHA512_KEY_OID => SecretKeyType::HmacSha512,
            _ => SecretKeyType::Unknown(*oid),
        }
    }

    /// Return the `ObjectIdentifier` for a `SecretKeyType`
    pub fn to_oid(&self) -> ObjectIdentifier {
        match self {
            SecretKeyType::Aes => oid::AES_GROUP_KEY_OID,
            SecretKeyType::Aes128Cbc => oid::AES_128_CBC_KEY_OID,
            SecretKeyType::Aes192Cbc => oid::AES_192_CBC_KEY_OID,
            SecretKeyType::Aes256Cbc => oid::AES_256_CBC_KEY_OID,
            SecretKeyType::DesCbc => oid::DES_CBC_KEY_OID,
            SecretKeyType::DesEde3Cbc => oid::DES_EDE3_CBC_KEY_OID,
            SecretKeyType::Blowfish => oid::BLOWFISH_KEY_OID,
            SecretKeyType::Rc2Cbc => oid::RC2_CBC_KEY_OID,
            SecretKeyType::Rc4 => oid::RC4_KEY_OID,
            SecretKeyType::Camelia => oid::CAMELIA_KEY_OID,
            SecretKeyType::HmacSha1 => oid::HMAC_SHA1_KEY_OID,
            SecretKeyType::HmacSha224 => oid::HMAC_SHA224_KEY_OID,
            SecretKeyType::HmacSha256 => oid::HMAC_SHA256_KEY_OID,
            SecretKeyType::HmacSha384 => oid::HMAC_SHA384_KEY_OID,
            SecretKeyType::HmacSha512 => oid::HMAC_SHA512_KEY_OID,
            SecretKeyType::Unknown(oid) => *oid,
        }
    }

    /// returns default key length in bytes
    pub(crate) fn default_len(&self) -> Option<usize> {
        match self {
            SecretKeyType::Aes128Cbc => Some(16),                            // 128 bit
            SecretKeyType::Aes192Cbc => Some(24),                            // 196 bit
            SecretKeyType::Aes256Cbc => Some(32),                            // 256 bit
            SecretKeyType::HmacSha1 | SecretKeyType::HmacSha224 => Some(64), // 512 bit
            SecretKeyType::HmacSha256 | SecretKeyType::HmacSha384 | SecretKeyType::HmacSha512 => Some(128), // 1024 bit
            _ => None,
        }
    }
}

impl FromStr for SecretKeyType {
    type Err = der::oid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecretKeyType::from_oid(&ObjectIdentifier::new(s)?))
    }
}

/// Implements debug for formatted output
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKeyChain")
            .field("key_type", &self.key_type)
            .field("key", &"<KEY>")
            .field("local_key_id", &hex::encode(&self.local_key_id))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use der::oid::ObjectIdentifier;
    use rand::rngs::ThreadRng;

    use crate::{
        LocalKeyId,
        oid::*,
        secret::{Secret, SecretKeyBuilderError, SecretKeyType},
    };

    #[test]
    fn test_from_oid_str() {
        assert_eq!(SecretKeyType::Aes, AES_GROUP_KEY_OID.to_string().parse().unwrap(),);
        assert_eq!(
            SecretKeyType::Aes128Cbc,
            AES_128_CBC_KEY_OID.to_string().parse().unwrap(),
        );
        assert_eq!(
            SecretKeyType::Aes192Cbc,
            AES_192_CBC_KEY_OID.to_string().parse().unwrap(),
        );
        assert_eq!(
            SecretKeyType::Aes256Cbc,
            AES_256_CBC_KEY_OID.to_string().parse().unwrap(),
        );
        assert_eq!(SecretKeyType::DesCbc, DES_CBC_KEY_OID.to_string().parse().unwrap(),);
        assert_eq!(
            SecretKeyType::DesEde3Cbc,
            DES_EDE3_CBC_KEY_OID.to_string().parse().unwrap(),
        );
        assert_eq!(SecretKeyType::Blowfish, BLOWFISH_KEY_OID.to_string().parse().unwrap(),);
        assert_eq!(SecretKeyType::Rc2Cbc, RC2_CBC_KEY_OID.to_string().parse().unwrap(),);
        assert_eq!(SecretKeyType::Rc4, RC4_KEY_OID.to_string().parse().unwrap(),);
        assert_eq!(SecretKeyType::Camelia, CAMELIA_KEY_OID.to_string().parse().unwrap(),);
        assert_eq!(SecretKeyType::HmacSha1, HMAC_SHA1_KEY_OID.to_string().parse().unwrap(),);
        assert_eq!(
            SecretKeyType::HmacSha224,
            HMAC_SHA224_KEY_OID.to_string().parse().unwrap(),
        );
        assert_eq!(
            SecretKeyType::HmacSha256,
            HMAC_SHA256_KEY_OID.to_string().parse().unwrap(),
        );
        assert_eq!(
            SecretKeyType::HmacSha384,
            HMAC_SHA384_KEY_OID.to_string().parse().unwrap(),
        );
        assert_eq!(
            SecretKeyType::HmacSha512,
            HMAC_SHA512_KEY_OID.to_string().parse().unwrap(),
        );

        // Unknown OID check (any OID not in the mapping)
        let dummy_oid = ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7");
        assert_eq!(SecretKeyType::Unknown(dummy_oid), "1.2.3.4.5.6.7".parse().unwrap(),);
    }

    #[test]
    fn test_invalid_oid() {
        assert!("bad_oid".parse::<SecretKeyType>().is_err());
    }

    #[test]
    fn test_from_oid() {
        assert_eq!(SecretKeyType::Aes, SecretKeyType::from_oid(&AES_GROUP_KEY_OID));
        assert_eq!(SecretKeyType::Aes128Cbc, SecretKeyType::from_oid(&AES_128_CBC_KEY_OID));
        assert_eq!(SecretKeyType::Aes192Cbc, SecretKeyType::from_oid(&AES_192_CBC_KEY_OID));
        assert_eq!(SecretKeyType::Aes256Cbc, SecretKeyType::from_oid(&AES_256_CBC_KEY_OID));
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
    fn test_getters() {
        let initial_key = vec![1, 2, 3];
        let initial_key_type = SecretKeyType::Aes128Cbc;
        let initial_local_key_id: LocalKeyId = vec![10, 20, 30].into();

        let secret = Secret {
            key: initial_key.clone(),
            key_type: initial_key_type,
            local_key_id: initial_local_key_id.clone(),
        };

        // Test getters for initial values
        assert_eq!(secret.key(), &initial_key[..]);
        assert_eq!(secret.key_type(), initial_key_type);
        assert_eq!(secret.local_key_id(), &initial_local_key_id);
    }

    #[test]
    fn test_secret_builder() {
        let secret = Secret::builder(SecretKeyType::Aes256Cbc).build();
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert_eq!(secret.key_type(), SecretKeyType::Aes256Cbc);
            assert_eq!(secret.key().len(), 32);
        }
    }

    #[test]
    fn test_secret_builder_with_aes128_generic() {
        let secret = Secret::builder(SecretKeyType::Aes).with_length(16).build();
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert_eq!(secret.key_type(), SecretKeyType::Aes);
            assert_eq!(secret.key().len(), 16);
        }
    }

    #[test]
    fn test_secret_builder_with_aes192() {
        let secret = Secret::builder(SecretKeyType::Aes192Cbc).build();
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert_eq!(secret.key_type(), SecretKeyType::Aes192Cbc);
            assert_eq!(secret.key().len(), 24);
        }
    }

    #[test]
    fn test_secret_builder_with_missing_len() {
        let secret = Secret::builder(SecretKeyType::Aes).build();
        assert!(secret.is_err());
        if let Err(e) = secret {
            assert_eq!(e, SecretKeyBuilderError::MissingKeyLength);
        }
    }

    #[test]
    fn test_secret_builder_with_val() {
        let key_val = [[17u8; 32]].as_flattened().to_vec();
        let secret = Secret::builder(SecretKeyType::Aes).with_key(key_val.clone()).build();
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert_eq!(secret.key_type(), SecretKeyType::Aes);
            assert_eq!(secret.key().len(), 32);
            assert_eq!(key_val, secret.key());
        }
    }

    #[test]
    fn test_secret_builder_with_val_n_id() {
        let key_val = [[17u8; 32]].as_flattened().to_vec();
        let key_id_val: LocalKeyId = [[0u8; 20]].as_flattened().into();
        let secret = Secret::builder(SecretKeyType::Aes256Cbc)
            .with_key(key_val.clone())
            .with_local_key_id(key_id_val.clone())
            .build();
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert_eq!(secret.key_type(), SecretKeyType::Aes256Cbc);
            assert_eq!(secret.key().len(), 32);
            assert_eq!(key_val, secret.key());
            assert_eq!(&key_id_val, secret.local_key_id());
        }
    }

    #[test]
    fn test_secret_builder_with_non_default_rng() {
        let secret = Secret::builder(SecretKeyType::Aes256Cbc)
            .with_rng(ThreadRng::default())
            .build();
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert_eq!(secret.key_type(), SecretKeyType::Aes256Cbc);
            assert_eq!(secret.key().len(), 32);
        }
    }
}
