use cms::{
    cert::{
        x509::attr::{Attribute, AttributeValue, Attributes},
        x509::spki::AlgorithmIdentifierOwned,
    },
    content_info::{CmsVersion, ContentInfo},
    encrypted_data::EncryptedData,
    enveloped_data::EncryptedContentInfo,
};
use der::{
    asn1::{BmpString, ContextSpecific, ObjectIdentifier, OctetString, OctetStringRef, SetOfVec},
    Any, Decode, Encode,
};
use hmac::{digest::Digest, Mac};
use pkcs12::{
    cert_type::CertBag,
    digest_info::DigestInfo,
    kdf,
    mac_data::MacData,
    pbe_params::EncryptedPrivateKeyInfo,
    safe_bag::{SafeBag, SafeContents},
};
use pkcs5::pbes2;
use rand::random;
use sha1::Sha1;
use sha2::Sha256;

#[cfg(feature = "pbes1")]
use {
    crate::pbes1::{PbeMode, Pbes1},
    der::{Reader, SliceReader, SliceWriter},
};

use crate::{
    error::Error,
    keystore::{Certificate, EncryptionAlgorithm, MacAlgorithm, PrivateKeyChain},
    oid, Result,
};

pub struct ParsedKeyChain {
    pub friendly_name: Option<String>,
    pub key: PrivateKeyChain,
}

pub struct ParsedCertificate {
    pub friendly_name: Option<String>,
    pub local_key_id: Option<Vec<u8>>,
    pub trusted: bool,
    pub cert: Certificate,
}

pub struct ParsedAuthSafe {
    pub keys: Vec<ParsedKeyChain>,
    pub certs: Vec<ParsedCertificate>,
}

pub fn verify_mac(mac_data: &MacData, password: &str, data: &[u8]) -> Result<()> {
    match mac_data.mac.algorithm.oid {
        oid::SHA1_OID => {
            let key = kdf::derive_key_utf8::<Sha1>(
                password,
                mac_data.mac_salt.as_bytes(),
                kdf::Pkcs12KeyType::Mac,
                mac_data.iterations as _,
                Sha1::output_size(),
            )?;
            let mut hmac = hmac::Hmac::<Sha1>::new_from_slice(&key).map_err(|_| Error::InvalidLength)?;
            hmac.update(data);
            hmac.verify_slice(mac_data.mac.digest.as_bytes())?;
            Ok(())
        }
        oid::SHA256_OID => {
            let key = kdf::derive_key_utf8::<Sha256>(
                password,
                mac_data.mac_salt.as_bytes(),
                kdf::Pkcs12KeyType::Mac,
                mac_data.iterations as _,
                Sha256::output_size(),
            )?;
            let mut hmac = hmac::Hmac::<Sha256>::new_from_slice(&key).map_err(|_| Error::InvalidLength)?;
            hmac.update(data);
            hmac.verify_slice(mac_data.mac.digest.as_bytes())?;
            Ok(())
        }
        _ => Err(Error::UnsupportedEncryptionScheme),
    }
}

pub fn parse_auth_safe(safe: &ContentInfo, password: &str) -> Result<ParsedAuthSafe> {
    let data = match safe.content_type {
        oid::CONTENT_TYPE_DATA_OID => {
            let os = OctetString::from_der(&safe.content.to_der()?)?.as_bytes().to_vec();
            os
        }
        oid::CONTENT_TYPE_ENCRYPTED_DATA_OID => {
            let enc_data = EncryptedData::from_der(&safe.content.to_der()?)?;
            if enc_data.version != CmsVersion::V0 {
                return Err(Error::InvalidVersion);
            }
            if let Some(data) = enc_data
                .enc_content_info
                .encrypted_content
                .as_ref()
                .map(|os| os.as_bytes())
            {
                decrypt(&enc_data.enc_content_info.content_enc_alg, data, password)?
            } else {
                Vec::new()
            }
        }
        _ => {
            return Err(Error::UnsupportedContentType);
        }
    };

    parse_bags(SafeContents::from_der(&data)?, password)
}

fn decrypt(alg: &AlgorithmIdentifierOwned, data: &[u8], password: &str) -> Result<Vec<u8>> {
    match alg.oid {
        oid::PBES2_OID => {
            let params = alg.parameters.as_ref().ok_or(Error::InvalidParameters)?.to_der()?;

            let params = pbes2::Parameters::from_der(&params)?;

            Ok(params
                .decrypt(password.as_bytes(), data)
                .map_err(|e| Error::Pkcs5Error(format!("{e}")))?)
        }
        #[cfg(feature = "pbes1")]
        oid::PBE_WITH_SHA_AND_40BIT_RC2_CBC_OID | oid::PBE_WITH_SHA_AND3_KEY_TRIPLE_DES_CBC_OID => {
            let params = alg.parameters.as_ref().ok_or(Error::InvalidParameters)?.to_der()?;

            let mut reader = SliceReader::new(&params)?;
            let (salt, iterations) = reader.sequence(|reader| {
                let salt = OctetStringRef::decode(reader)?.as_bytes().to_vec();
                let iterations: u64 = reader.decode()?;
                Ok((salt, iterations))
            })?;

            Pbes1::new(alg.oid, &salt, iterations, PbeMode::Decrypt).encrypt_decrypt(data, password)
        }
        _ => Err(Error::UnsupportedEncryptionScheme),
    }
}

fn encrypt(
    alg: EncryptionAlgorithm,
    iterations: u64,
    data: &[u8],
    password: &str,
) -> Result<(AlgorithmIdentifierOwned, Vec<u8>)> {
    match alg {
        EncryptionAlgorithm::PbeWithHmacSha256AndAes256 => {
            let salt: [u8; 32] = random();
            let iv: [u8; 16] = random();
            let params = pbes2::Parameters::pbkdf2_sha256_aes256cbc(iterations as _, &salt, &iv)
                .map_err(|e| Error::Pkcs5Error(e.to_string()))?;

            let encrypted = params
                .encrypt(password.as_bytes(), data)
                .map_err(|e| Error::Pkcs5Error(format!("{e}")))?;

            let alg_id = AlgorithmIdentifierOwned {
                oid: alg.as_oid(),
                parameters: Some(Any::from_der(&params.to_der()?)?),
            };

            Ok((alg_id, encrypted))
        }
        #[cfg(feature = "pbes1")]
        EncryptionAlgorithm::PbeWithShaAnd40BitRc4Cbc | EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc => {
            let salt: [u8; 20] = random();
            let encrypted =
                Pbes1::new(alg.as_oid(), &salt, iterations, PbeMode::Encrypt).encrypt_decrypt(data, password)?;

            let mut buf = vec![0u8; 64];
            let mut writer = SliceWriter::new(&mut buf);
            let salt = OctetStringRef::new(&salt)?;

            writer.sequence((salt.encoded_len()? + iterations.encoded_len()?)?, |writer| {
                salt.encode(writer)?;
                iterations.encode(writer)?;
                Ok(())
            })?;
            let params = writer.finish()?;

            let alg_id = AlgorithmIdentifierOwned {
                oid: alg.as_oid(),
                parameters: Some(Any::from_der(params)?),
            };
            Ok((alg_id, encrypted))
        }
        #[cfg(not(feature = "pbes1"))]
        _ => Err(Error::UnsupportedEncryptionScheme),
    }
}

fn get_bag_attribute(oid: &ObjectIdentifier, bag: &SafeBag) -> Option<Vec<u8>> {
    if let Some(ref attrs) = bag.bag_attributes {
        attrs.iter().find_map(|a| {
            if a.oid == *oid {
                a.values.iter().next().and_then(|a| a.to_der().ok())
            } else {
                None
            }
        })
    } else {
        None
    }
}

fn parse_bags(bags: SafeContents, password: &str) -> Result<ParsedAuthSafe> {
    let mut keys = Vec::new();
    let mut certs = Vec::new();

    for bag in bags {
        let local_key_id = get_bag_attribute(&oid::LOCAL_KEY_ID_OID, &bag)
            .and_then(|a| OctetString::from_der(&a).ok().map(|a| a.as_bytes().to_vec()));

        let friendly_name = get_bag_attribute(&oid::FRIENDLY_NAME_OID, &bag)
            .and_then(|n| BmpString::from_der(&n).ok().map(|a| a.to_string()));

        let trusted = get_bag_attribute(&oid::ORACLE_TRUSTED_KEY_USAGE_OID, &bag)
            .and_then(|n| ObjectIdentifier::from_der(&n).ok())
            .map(|o| o == oid::ANY_EXTENDED_USAGE_OID)
            .unwrap_or_default();

        match bag.bag_id {
            oid::PKCS_12_CERT_BAG_OID => {
                let cs: ContextSpecific<CertBag> = ContextSpecific::from_der(&bag.bag_value)?;
                if cs.value.cert_id != oid::CERT_TYPE_X509_CERTIFICATE_OID {
                    return Err(Error::UnsupportedCertificateType);
                }
                let cert = Certificate::from_der(cs.value.cert_value.as_bytes())?;
                certs.push(ParsedCertificate {
                    friendly_name,
                    local_key_id,
                    trusted,
                    cert,
                });
            }
            oid::PKCS_12_PKCS8_KEY_BAG_OID => {
                let cs: ContextSpecific<EncryptedPrivateKeyInfo> = ContextSpecific::from_der(&bag.bag_value)?;

                let decrypted = decrypt(
                    &cs.value.encryption_algorithm,
                    cs.value.encrypted_data.as_bytes(),
                    password,
                )?;

                if let Some(local_key_id) = local_key_id {
                    let key = PrivateKeyChain {
                        key: decrypted,
                        local_key_id,
                        chain: vec![],
                    };
                    keys.push(ParsedKeyChain { friendly_name, key });
                }
            }
            _ => {}
        }
    }

    Ok(ParsedAuthSafe { keys, certs })
}

pub fn certificate_to_safe_bag(
    certificate: &Certificate,
    friendly_name: &str,
    local_key_id: Option<&[u8]>,
    trusted: bool,
) -> Result<SafeBag> {
    let mut bag_attributes = Attributes::new();

    let friendly_name =
        SetOfVec::<AttributeValue>::from_iter([Any::from_der(&BmpString::from_utf8(friendly_name)?.to_der()?)?])?;

    bag_attributes.insert(Attribute {
        oid: oid::FRIENDLY_NAME_OID,
        values: friendly_name,
    })?;

    if let Some(local_key_id) = local_key_id {
        let local_key_id =
            SetOfVec::<AttributeValue>::from_iter([Any::from_der(&OctetStringRef::new(local_key_id)?.to_der()?)?])?;

        bag_attributes.insert(Attribute {
            oid: oid::LOCAL_KEY_ID_OID,
            values: local_key_id,
        })?;
    }

    if trusted {
        let key_usage =
            SetOfVec::<AttributeValue>::from_iter([Any::from_der(&oid::ANY_EXTENDED_USAGE_OID.to_der()?)?])?;

        bag_attributes.insert(Attribute {
            oid: oid::ORACLE_TRUSTED_KEY_USAGE_OID,
            values: key_usage,
        })?;
    }

    let cert_bag = CertBag {
        cert_id: oid::CERT_TYPE_X509_CERTIFICATE_OID,
        cert_value: OctetString::new(certificate.data.clone())?,
    };
    Ok(SafeBag {
        bag_id: oid::PKCS_12_CERT_BAG_OID,
        bag_value: cert_bag.to_der()?,
        bag_attributes: Some(bag_attributes),
    })
}

pub fn private_key_to_safe_bag(
    key: &PrivateKeyChain,
    friendly_name: &str,
    algorithm: EncryptionAlgorithm,
    iterations: u64,
    password: &str,
) -> Result<SafeBag> {
    let mut bag_attributes = Attributes::new();

    let friendly_name =
        SetOfVec::<AttributeValue>::from_iter([Any::from_der(&BmpString::from_utf8(friendly_name)?.to_der()?)?])?;

    bag_attributes.insert(Attribute {
        oid: oid::FRIENDLY_NAME_OID,
        values: friendly_name,
    })?;

    let local_key_id =
        SetOfVec::<AttributeValue>::from_iter([Any::from_der(&OctetStringRef::new(&key.local_key_id)?.to_der()?)?])?;

    bag_attributes.insert(Attribute {
        oid: oid::LOCAL_KEY_ID_OID,
        values: local_key_id,
    })?;

    let (alg_id, encrypted) = encrypt(algorithm, iterations, &key.key, password)?;

    let pk_info = EncryptedPrivateKeyInfo {
        encryption_algorithm: alg_id,
        encrypted_data: OctetString::new(encrypted)?,
    }
    .to_der()?;

    Ok(SafeBag {
        bag_id: oid::PKCS_12_PKCS8_KEY_BAG_OID,
        bag_value: pk_info,
        bag_attributes: Some(bag_attributes),
    })
}

pub fn cert_bags_to_auth_safe(
    bags: Vec<SafeBag>,
    algorithm: EncryptionAlgorithm,
    iterations: u64,
    password: &str,
) -> Result<ContentInfo> {
    let data = bags.to_der()?;
    let (alg_id, encrypted) = encrypt(algorithm, iterations, &data, password)?;

    let encrypted_data = EncryptedData {
        version: CmsVersion::V0,
        enc_content_info: EncryptedContentInfo {
            content_type: oid::CONTENT_TYPE_DATA_OID,
            content_enc_alg: alg_id,
            encrypted_content: Some(OctetString::new(encrypted)?),
        },
        unprotected_attrs: None,
    };

    Ok(ContentInfo {
        content_type: oid::CONTENT_TYPE_ENCRYPTED_DATA_OID,
        content: Any::from_der(&encrypted_data.to_der()?)?,
    })
}

pub fn key_bags_to_auth_safe(bags: Vec<SafeBag>) -> Result<ContentInfo> {
    Ok(ContentInfo {
        content_type: oid::CONTENT_TYPE_DATA_OID,
        content: Any::from_der(&OctetString::new(bags.to_der()?)?.to_der()?)?,
    })
}

pub fn compute_mac(data: &[u8], algorithm: MacAlgorithm, iterations: u64, password: &str) -> Result<MacData> {
    let (oid, salt, digest) = match algorithm {
        MacAlgorithm::HmacSha1 => {
            let salt: [u8; 20] = random();
            let key = kdf::derive_key_utf8::<Sha1>(
                password,
                &salt,
                kdf::Pkcs12KeyType::Mac,
                iterations as _,
                Sha1::output_size(),
            )?;
            let mut hmac = hmac::Hmac::<Sha1>::new_from_slice(&key).map_err(|_| Error::InvalidLength)?;
            hmac.update(data);
            (oid::SHA1_OID, salt.to_vec(), hmac.finalize().into_bytes().to_vec())
        }
        MacAlgorithm::HmacSha256 => {
            let salt: [u8; 32] = random();
            let key = kdf::derive_key_utf8::<Sha256>(
                password,
                &salt,
                kdf::Pkcs12KeyType::Mac,
                iterations as _,
                Sha256::output_size(),
            )?;
            let mut hmac = hmac::Hmac::<Sha256>::new_from_slice(&key).map_err(|_| Error::InvalidLength)?;
            hmac.update(data);
            (oid::SHA256_OID, salt.to_vec(), hmac.finalize().into_bytes().to_vec())
        }
    };

    Ok(MacData {
        mac: DigestInfo {
            algorithm: AlgorithmIdentifierOwned { oid, parameters: None },
            digest: OctetString::new(digest)?,
        },
        mac_salt: OctetString::new(salt)?,
        iterations: iterations as _,
    })
}
