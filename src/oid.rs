use der::asn1::ObjectIdentifier;

pub const FRIENDLY_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.20");
pub const LOCAL_KEY_ID_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");
pub const PBE_WITH_SHA_AND3_KEY_TRIPLE_DES_CBC_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.3");
pub const PBE_WITH_SHA_AND_40BIT_RC2_CBC_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.6");
pub const CONTENT_TYPE_ENCRYPTED_DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.6");
pub const CONTENT_TYPE_DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
pub const ORACLE_TRUSTED_KEY_USAGE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.113894.746875.1.1");
pub const ANY_EXTENDED_USAGE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37.0");
pub const PBES2_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.13");
pub const SHA1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
pub const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
pub const CERT_TYPE_X509_CERTIFICATE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.22.1");
pub const PKCS_12_PKCS8_KEY_BAG_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.2");
pub const PKCS_12_CERT_BAG_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.3");
