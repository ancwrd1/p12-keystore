use der::oid::ObjectIdentifier;

macro_rules! define_oids {
    {
        $(
            $(#[$meta:meta])*
            { $name:ident, $oid:literal $(, $doc:literal)? }
        ),* $(,)?
    } => {
        $(
            $(#[$meta])*
            $(#[doc = $doc])?
            pub const $name: ObjectIdentifier = ObjectIdentifier::new_unwrap($oid);
        )*
    };
}

define_oids! {
    { FRIENDLY_NAME_OID, "1.2.840.113549.1.9.20", "PKCS#9 friendly name attribute" },
    { LOCAL_KEY_ID_OID, "1.2.840.113549.1.9.21", "PKCS#9 local key identifier attribute" },
    { PBE_WITH_SHA_AND3_KEY_TRIPLE_DES_CBC_OID, "1.2.840.113549.1.12.1.3", "PBE with SHA-1 and 3-key Triple DES-CBC" },
    { PBE_WITH_SHA_AND_40BIT_RC2_CBC_OID, "1.2.840.113549.1.12.1.6", "PBE with SHA-1 and 40-bit RC2-CBC" },
    { CONTENT_TYPE_ENCRYPTED_DATA_OID, "1.2.840.113549.1.7.6", "PKCS#7 encrypted data content type" },
    { CONTENT_TYPE_DATA_OID, "1.2.840.113549.1.7.1", "PKCS#7 data content type" },
    { ORACLE_TRUSTED_KEY_USAGE_OID, "2.16.840.1.113894.746875.1.1", "Oracle trusted key usage extension" },
    { ANY_EXTENDED_USAGE_OID, "2.5.29.37.0", "Any extended key usage" },
    { PBES2_OID, "1.2.840.113549.1.5.13", "PKCS#5 PBES2 encryption scheme" },
    { SHA1_OID, "1.3.14.3.2.26", "SHA-1 hash algorithm" },
    { SHA256_OID, "2.16.840.1.101.3.4.2.1", "SHA-256 hash algorithm" },
    { CERT_TYPE_X509_CERTIFICATE_OID, "1.2.840.113549.1.9.22.1", "X.509 certificate type" },
    { PKCS_12_PKCS8_KEY_BAG_OID, "1.2.840.113549.1.12.10.1.2", "PKCS#12 PKCS#8 shrouded key bag" },
    { PKCS_12_CERT_BAG_OID, "1.2.840.113549.1.12.10.1.3", "PKCS#12 certificate bag" },
    { PKCS_12_SECRET_BAG_OID, "1.2.840.113549.1.12.10.1.5", "PKCS#12 secret bag" },
    { AES_GROUP_KEY_OID, "2.16.840.1.101.3.4.1", "AES encryption algorithm group" },
    { AES_128_CBC_KEY_OID, "2.16.840.1.101.3.4.1.2", "AES-128 in CBC mode" },
    { AES_192_CBC_KEY_OID, "2.16.840.1.101.3.4.1.22", "AES-192 in CBC mode" },
    { AES_256_CBC_KEY_OID, "2.16.840.1.101.3.4.1.42", "AES-256 in CBC mode" },
    { DES_CBC_KEY_OID, "1.3.14.3.2.7", "DES in CBC mode" },
    { DES_EDE3_CBC_KEY_OID, "1.2.840.113549.3.7", "Triple DES (3DES) in CBC mode" },
    { BLOWFISH_KEY_OID, "1.3.6.1.4.1.3029.1.1.2", "Blowfish encryption algorithm" },
    { RC2_CBC_KEY_OID, "1.2.840.113549.3.2", "RC2 in CBC mode" },
    { RC4_KEY_OID, "1.2.840.113549.3.4", "RC4 stream cipher" },
    { HMAC_SHA1_KEY_OID, "1.2.840.113549.2.7", "HMAC with SHA-1" },
    { HMAC_SHA224_KEY_OID, "1.2.840.113549.2.8", "HMAC with SHA-224" },
    { HMAC_SHA256_KEY_OID, "1.2.840.113549.2.9", "HMAC with SHA-256" },
    { HMAC_SHA384_KEY_OID, "1.2.840.113549.2.10", "HMAC with SHA-384" },
    { HMAC_SHA512_KEY_OID, "1.2.840.113549.2.11", "HMAC with SHA-512" },
    { CAMELIA_KEY_OID, "1.2.392.200011.61.1.1.1.4", "Camellia encryption algorithm" },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_values() {
        assert_eq!(SHA256_OID.to_string(), "2.16.840.1.101.3.4.2.1");
        assert_eq!(AES_256_CBC_KEY_OID.to_string(), "2.16.840.1.101.3.4.1.42");
    }
}
