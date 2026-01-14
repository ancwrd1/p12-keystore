use cbc::cipher::{
    BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit,
    block_padding::Pkcs7,
};
use der::oid::ObjectIdentifier;
use des::TdesEde3;
use pkcs12::kdf;
use rc2::Rc2;
use sha1::Sha1;

use crate::{Result, error::Error, oid};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum PbeMode {
    Encrypt,
    Decrypt,
}

pub struct Pbes1<'a> {
    alg_oid: ObjectIdentifier,
    salt: &'a [u8],
    iterations: u64,
    mode: PbeMode,
}

impl<'a> Pbes1<'a> {
    pub fn new(alg_oid: ObjectIdentifier, salt: &'a [u8], iterations: u64, mode: PbeMode) -> Self {
        Self {
            alg_oid,
            salt,
            iterations,
            mode,
        }
    }

    fn cbc<T>(&self, data: &[u8], password: &str, size: usize) -> Result<Vec<u8>>
    where
        T: KeyInit + BlockCipherDecrypt + BlockCipherEncrypt,
    {
        let key = kdf::derive_key_utf8::<Sha1>(
            password,
            self.salt,
            kdf::Pkcs12KeyType::EncryptionKey,
            self.iterations as _,
            size,
        )?;

        let iv = kdf::derive_key_utf8::<Sha1>(password, self.salt, kdf::Pkcs12KeyType::Iv, self.iterations as _, 8)?;

        if self.mode == PbeMode::Encrypt {
            let cipher = cbc::Encryptor::<T>::new_from_slices(&key, &iv).map_err(|_| Error::InvalidLength)?;
            Ok(cipher.encrypt_padded_vec::<Pkcs7>(data))
        } else {
            let cipher = cbc::Decryptor::<T>::new_from_slices(&key, &iv).map_err(|_| Error::InvalidLength)?;
            Ok(cipher
                .decrypt_padded_vec::<Pkcs7>(data)
                .map_err(|_| Error::UnpadError)?)
        }
    }

    pub fn encrypt_decrypt(&self, data: &[u8], password: &str) -> Result<Vec<u8>> {
        match self.alg_oid {
            oid::PBE_WITH_SHA_AND3_KEY_TRIPLE_DES_CBC_OID => self.cbc::<TdesEde3>(data, password, 24),
            oid::PBE_WITH_SHA_AND_40BIT_RC2_CBC_OID => self.cbc::<Rc2>(data, password, 5),
            _ => Err(Error::UnsupportedEncryptionScheme),
        }
    }
}
