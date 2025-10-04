use p12_keystore::{EncryptionAlgorithm, KeyStore, MacAlgorithm};

const PBES1_KEYSTORE: &[u8] = include_bytes!("../tests/assets/pbes1-keystore.p12");
const PBES2_KEYSTORE: &[u8] = include_bytes!("../tests/assets/pbes2-keystore.p12");
const PBES1_TRUSTSTORE: &[u8] = include_bytes!("../tests/assets/pbes1-truststore.p12");
const PBES2_TRUSTSTORE: &[u8] = include_bytes!("../tests/assets/pbes2-truststore.p12");
const PFX_TRUSTSTORE: &[u8] = include_bytes!("../tests/assets/pfx-ed25519.pfx");

const PASSWORD: &str = "changeit";
const ITERATIONS: u64 = 1000;

fn common_read_test(pkcs12: &[u8]) {
    let keystore = KeyStore::from_pkcs12(pkcs12, PASSWORD).unwrap();

    for e in keystore.entries() {
        println!("{}: {:#?}", e.0, e.1);
    }
}

fn common_write_test(
    name: &str,
    pkcs12: &[u8],
    enc_alg: EncryptionAlgorithm,
    enc_iterations: u64,
    mac_alg: MacAlgorithm,
    mac_iterations: u64,
) {
    let keystore = KeyStore::from_pkcs12(pkcs12, PASSWORD).unwrap();

    let data = keystore
        .writer(PASSWORD)
        .encryption_algorithm(enc_alg)
        .encryption_iterations(enc_iterations)
        .mac_algorithm(mac_alg)
        .mac_iterations(mac_iterations)
        .write()
        .expect(name);

    //std::fs::write(format!("/tmp/{name}.p12"), &data).unwrap();
    KeyStore::from_pkcs12(&data, PASSWORD).expect(name);
}

#[test]
fn test_parse_pbes1_keystore() {
    common_read_test(PBES1_KEYSTORE);
}

#[test]
fn test_parse_pbes2_keystore() {
    common_read_test(PBES2_KEYSTORE);
}

#[test]
fn test_parse_pbes1_truststore() {
    common_read_test(PBES1_TRUSTSTORE);
}

#[test]
fn test_parse_pbes2_truststore() {
    common_read_test(PBES2_TRUSTSTORE);
}

#[test]
fn test_parse_self_signed_pfx() {
    let keystore = KeyStore::from_pkcs12(PFX_TRUSTSTORE, PASSWORD).unwrap();

    for e in keystore.entries() {
        println!("{}: {:#?}", e.0, e.1)
    }

    let key_chain = keystore.private_key_chain().unwrap().1;

    assert_eq!(
        1,
        key_chain.certs().len(),
        "self-signed certificates must not be duplicated"
    );
}

#[test]
fn test_write_pbes1_3des_keystore() {
    common_write_test(
        "3des-sha1",
        PBES1_KEYSTORE,
        EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc,
        ITERATIONS,
        MacAlgorithm::HmacSha1,
        ITERATIONS,
    );
    common_write_test(
        "3des-sha256",
        PBES1_KEYSTORE,
        EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc,
        ITERATIONS,
        MacAlgorithm::HmacSha256,
        ITERATIONS,
    );
}

#[test]
fn test_write_pbes1_40rc2_keystore() {
    common_write_test(
        "40rc2-sha1",
        PBES1_KEYSTORE,
        EncryptionAlgorithm::PbeWithShaAnd40BitRc4Cbc,
        ITERATIONS,
        MacAlgorithm::HmacSha1,
        ITERATIONS,
    );

    common_write_test(
        "40rc2-sha256",
        PBES1_KEYSTORE,
        EncryptionAlgorithm::PbeWithShaAnd40BitRc4Cbc,
        ITERATIONS,
        MacAlgorithm::HmacSha256,
        ITERATIONS,
    );
}

#[test]
fn test_write_pbes2_keystore() {
    common_write_test(
        "aes256-sha1",
        PBES2_KEYSTORE,
        EncryptionAlgorithm::PbeWithHmacSha256AndAes256,
        ITERATIONS,
        MacAlgorithm::HmacSha1,
        ITERATIONS,
    );

    common_write_test(
        "aes256-sha256",
        PBES2_KEYSTORE,
        EncryptionAlgorithm::PbeWithHmacSha256AndAes256,
        ITERATIONS,
        MacAlgorithm::HmacSha256,
        ITERATIONS,
    );
}

#[test]
fn test_write_pbes1_3des_truststore() {
    common_write_test(
        "3des-sha1",
        PBES1_TRUSTSTORE,
        EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc,
        ITERATIONS,
        MacAlgorithm::HmacSha1,
        ITERATIONS,
    );
    common_write_test(
        "3des-sha256",
        PBES1_TRUSTSTORE,
        EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc,
        ITERATIONS,
        MacAlgorithm::HmacSha256,
        ITERATIONS,
    );
}

#[test]
fn test_write_pbes1_40rc2_truststore() {
    common_write_test(
        "40rc2-sha1",
        PBES1_TRUSTSTORE,
        EncryptionAlgorithm::PbeWithShaAnd40BitRc4Cbc,
        ITERATIONS,
        MacAlgorithm::HmacSha1,
        ITERATIONS,
    );

    common_write_test(
        "40rc2-sha256",
        PBES1_TRUSTSTORE,
        EncryptionAlgorithm::PbeWithShaAnd40BitRc4Cbc,
        ITERATIONS,
        MacAlgorithm::HmacSha256,
        ITERATIONS,
    );
}

#[test]
fn test_write_pbes2_truststore() {
    common_write_test(
        "aes256-sha1",
        PBES2_TRUSTSTORE,
        EncryptionAlgorithm::PbeWithHmacSha256AndAes256,
        ITERATIONS,
        MacAlgorithm::HmacSha1,
        ITERATIONS,
    );

    common_write_test(
        "aes256-sha256",
        PBES2_TRUSTSTORE,
        EncryptionAlgorithm::PbeWithHmacSha256AndAes256,
        ITERATIONS,
        MacAlgorithm::HmacSha256,
        ITERATIONS,
    );
}
