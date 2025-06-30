use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use p12_keystore::secret::{Secret, SecretKeyType};
use p12_keystore::{KeyStore, KeyStoreEntry};

const PBES1_KEYSTORE: &[u8] = include_bytes!("../tests/assets/pbes1-keystore.p12");
const PBES1_TRUSTSTORE: &[u8] = include_bytes!("../tests/assets/pbes1-truststore.p12");

const PBES2_KEYSTORE_AES_KEY: &[u8] = include_bytes!("assets/pbes2-keystore-with-secret-keys.p12");

const PASSWORD: &str = "changeit";

#[test]
fn test_keystore_api() {
    let seed_keystore = KeyStore::from_pkcs12(PBES1_KEYSTORE, PASSWORD).unwrap();

    let chains = seed_keystore
        .entries()
        .filter_map(|(_, e)| match e {
            KeyStoreEntry::PrivateKeyChain(chain) => Some(chain.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(chains.len(), 2);

    let seed_truststore = KeyStore::from_pkcs12(PBES1_TRUSTSTORE, PASSWORD).unwrap();

    let cert = seed_truststore
        .entries()
        .find_map(|(_, e)| match e {
            KeyStoreEntry::Certificate(cert) => Some(cert.clone()),
            _ => None,
        })
        .unwrap();

    let mut new_store = KeyStore::new();
    assert!(new_store.entries().collect::<Vec<_>>().is_empty());

    new_store.add_entry("c1", KeyStoreEntry::Certificate(cert.clone()));
    new_store.add_entry("c2", KeyStoreEntry::Certificate(cert.clone()));
    assert_eq!(new_store.entries_count(), 2);
    assert_eq!(new_store.entries().collect::<Vec<_>>().len(), 2);

    new_store.delete_entry("c1");
    new_store.delete_entry("c2");
    assert_eq!(new_store.entries().collect::<Vec<_>>().len(), 0);

    new_store.add_entry("e1", KeyStoreEntry::PrivateKeyChain(chains[0].clone()));
    assert_eq!(new_store.entries().collect::<Vec<_>>().len(), 1);
    assert!(new_store.entry("e1").is_some());
    assert_eq!(new_store.private_key_chain(), chains.first().map(|c| ("e1", c)));

    new_store.add_entry("e2", KeyStoreEntry::PrivateKeyChain(chains[1].clone()));
    assert_eq!(new_store.entries().collect::<Vec<_>>().len(), 2);
    assert_ne!(new_store.entry("e1"), new_store.entry("e2"));

    new_store.add_entry("c1", KeyStoreEntry::Certificate(cert.clone()));
    new_store.rename_entry("c1", "c2");

    let pfx = new_store.writer("mypwd").write().unwrap();
    let reloaded = KeyStore::from_pkcs12(&pfx, "mypwd").unwrap();

    assert!(matches!(reloaded.entry("c2"), Some(KeyStoreEntry::Certificate(_))));

    assert!(reloaded.entry("c1").is_none());

    assert!(matches!(reloaded.entry("e1"), Some(KeyStoreEntry::PrivateKeyChain(_))));

    assert!(matches!(reloaded.entry("e2"), Some(KeyStoreEntry::PrivateKeyChain(_))));

    assert_ne!(new_store.entry("e1"), new_store.entry("e2"));
}

#[test]
fn test_keystore_api_with_aes_key() {
    let keystore_with_ase_key = KeyStore::from_pkcs12(PBES2_KEYSTORE_AES_KEY, PASSWORD);

    assert!(&keystore_with_ase_key.is_ok());

    let keystore_with_ase_key = keystore_with_ase_key.unwrap();
    let entries = keystore_with_ase_key.entries();
    // assert!(8usize == keystore_with_ase_key.entries_count());

    entries.for_each(|(i, e)| println!("\"{}\" => {:?}", i, e));
}

#[test]
fn test_keystore_read_write_copy() {
    let keystore_with_keys = KeyStore::from_pkcs12(PBES2_KEYSTORE_AES_KEY, PASSWORD);

    assert!(&keystore_with_keys.is_ok());

    if let Ok(keystore_with_keys) = keystore_with_keys {
        let store_data = keystore_with_keys.writer("welcome1").write().unwrap();
        std::fs::write(format!("test_dummy.p12"), &store_data).unwrap();
        println!("{:?}", BASE64_STANDARD.encode(&store_data));
        let keystore_with_keys_copy = KeyStore::from_pkcs12(&store_data, "welcome1").unwrap();
        assert_eq!(13, keystore_with_keys_copy.entries_count());
    }
}

#[test]
fn test_keystore_create() {
    let mut keystore = KeyStore::new();
    let secret = Secret::builder(SecretKeyType::AES).with_lenght(24).build().unwrap();
    keystore.add_entry("test", KeyStoreEntry::Secret(secret));
    let store_data = keystore.writer("welcome1").write().unwrap();
    std::fs::write(format!("test_single_key.p12"), &store_data).unwrap();
    println!("{:?}", BASE64_STANDARD.encode(&store_data));
    let keystore_with_keys_copy = KeyStore::from_pkcs12(&store_data, "welcome1").unwrap();
    assert_eq!(1, keystore_with_keys_copy.entries_count());
}
