use p12_keystore::{KeyStore, KeyStoreEntry};

const PBES1_KEYSTORE: &[u8] = include_bytes!("../tests/assets/pbes1-keystore.p12");
const PBES1_TRUSTSTORE: &[u8] = include_bytes!("../tests/assets/pbes1-truststore.p12");
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
    assert_eq!(new_store.entries().collect::<Vec<_>>().len(), 2);

    new_store.delete_entry("c1");
    new_store.delete_entry("c2");
    assert_eq!(new_store.entries().collect::<Vec<_>>().len(), 0);

    new_store.add_entry("e1", KeyStoreEntry::PrivateKeyChain(chains[0].clone()));
    assert_eq!(new_store.entries().collect::<Vec<_>>().len(), 1);
    assert!(new_store.entry("e1").is_some());

    new_store.add_entry("e2", KeyStoreEntry::PrivateKeyChain(chains[1].clone()));
    assert_eq!(new_store.entries().collect::<Vec<_>>().len(), 2);
    assert_ne!(new_store.entry("e1"), new_store.entry("e2"));

    new_store.add_entry("c1", KeyStoreEntry::Certificate(cert.clone()));

    let pfx = new_store.writer("mypwd").write().unwrap();
    let reloaded = KeyStore::from_pkcs12(&pfx, "mypwd").unwrap();

    assert!(matches!(
        reloaded.entry("c1"),
        Some(KeyStoreEntry::Certificate(_))
    ));

    assert!(matches!(
        reloaded.entry("e1"),
        Some(KeyStoreEntry::PrivateKeyChain(_))
    ));

    assert!(matches!(
        reloaded.entry("e2"),
        Some(KeyStoreEntry::PrivateKeyChain(_))
    ));

    assert_ne!(new_store.entry("e1"), new_store.entry("e2"));
}
