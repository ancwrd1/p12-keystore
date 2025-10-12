extern crate core;

use p12_keystore::{
    KeyStore, KeyStoreEntry,
    secret::{Secret, SecretKeyType},
};

const PBES1_KEYSTORE: &[u8] = include_bytes!("../tests/assets/pbes1-keystore.p12");
const PBES1_TRUSTSTORE: &[u8] = include_bytes!("../tests/assets/pbes1-truststore.p12");

const PBES2_KEYSTORE_AES_KEY: &[u8] = include_bytes!("assets/pbes2-keystore-with-secret-keys.p12");

const PASSWORD: &str = "changeit";

pub const TEST_ENTRIES: &[(&str, &str, &[u8], &[u8])] = &[
    (
        "test-aes-128",
        "2.16.840.1.101.3.4.1",
        &[
            84, 105, 109, 101, 32, 49, 55, 53, 49, 50, 50, 51, 52, 54, 57, 52, 57, 54,
        ],
        &[
            172, 201, 97, 60, 99, 191, 163, 132, 238, 108, 93, 196, 11, 255, 233, 101,
        ],
    ),
    (
        "test-aes-192",
        "2.16.840.1.101.3.4.1",
        &[
            84, 105, 109, 101, 32, 49, 55, 53, 49, 50, 50, 51, 53, 49, 55, 48, 51, 50,
        ],
        &[
            73, 140, 43, 40, 230, 231, 22, 203, 240, 79, 248, 141, 204, 32, 223, 197, 138, 222, 168, 53, 236, 119, 83,
            50,
        ],
    ),
    (
        "test-aes-256-1",
        "2.16.840.1.101.3.4.1",
        &[
            84, 105, 109, 101, 32, 49, 55, 53, 49, 50, 50, 51, 53, 55, 50, 54, 51, 57,
        ],
        &[
            114, 28, 155, 249, 143, 125, 69, 23, 99, 131, 66, 164, 110, 7, 17, 122, 160, 167, 141, 23, 213, 121, 158,
            172, 15, 240, 161, 195, 144, 104, 84, 224,
        ],
    ),
    (
        "test-aes-256-2",
        "2.16.840.1.101.3.4.1",
        &[
            84, 105, 109, 101, 32, 49, 55, 53, 49, 50, 50, 51, 53, 56, 51, 50, 48, 57,
        ],
        &[
            35, 209, 207, 152, 106, 248, 196, 239, 54, 147, 208, 15, 243, 44, 207, 224, 86, 0, 88, 210, 71, 102, 105,
            227, 48, 171, 9, 153, 35, 113, 204, 211,
        ],
    ),
    (
        "test-blowfish-128",
        "1.3.6.1.4.1.3029.1.1.2",
        &[
            84, 105, 109, 101, 32, 49, 55, 53, 49, 50, 50, 51, 53, 57, 56, 55, 52, 55,
        ],
        &[179, 90, 152, 194, 13, 90, 101, 100, 154, 17, 70, 109, 1, 234, 8, 16],
    ),
    (
        "test-blowfish-256",
        "1.3.6.1.4.1.3029.1.1.2",
        &[
            84, 105, 109, 101, 32, 49, 55, 53, 49, 50, 50, 51, 54, 49, 57, 49, 57, 51,
        ],
        &[
            129, 50, 214, 204, 121, 204, 112, 75, 111, 47, 84, 150, 206, 80, 140, 185, 40, 117, 23, 136, 245, 29, 199,
            42, 103, 248, 29, 147, 150, 142, 31, 145,
        ],
    ),
    (
        "test-hmac-1",
        "1.2.840.113549.2.11",
        &[
            84, 105, 109, 101, 32, 49, 55, 53, 49, 48, 50, 55, 55, 50, 57, 55, 54, 50,
        ],
        &[
            106, 20, 43, 226, 248, 66, 6, 89, 212, 204, 12, 69, 172, 7, 73, 140, 85, 106, 210, 232, 190, 96, 21, 29,
            134, 105, 223, 171, 134, 96, 28, 161, 127, 192, 63, 47, 233, 30, 166, 37, 205, 209, 144, 129, 51, 155, 6,
            137, 156, 113, 16, 219, 109, 225, 141, 138, 93, 12, 108, 171, 143, 59, 4, 61,
        ],
    ),
    (
        "test_arc4_256",
        "1.2.840.113549.3.4",
        &[
            84, 105, 109, 101, 32, 49, 55, 53, 49, 49, 56, 53, 51, 57, 57, 49, 48, 55,
        ],
        &[
            181, 79, 218, 253, 182, 164, 99, 221, 135, 36, 234, 186, 52, 45, 120, 23, 99, 85, 11, 63, 183, 71, 152,
            186, 22, 43, 238, 91, 129, 78, 117, 78,
        ],
    ),
    (
        "test_camelia_128",
        "1.2.392.200011.61.1.1.1.4",
        &[
            84, 105, 109, 101, 32, 49, 55, 53, 49, 49, 56, 55, 54, 49, 50, 51, 49, 53,
        ],
        &[
            64, 83, 225, 149, 224, 12, 172, 151, 128, 107, 223, 233, 109, 254, 119, 92,
        ],
    ),
    (
        "test_camelia_256",
        "1.2.392.200011.61.1.1.1.4",
        &[
            84, 105, 109, 101, 32, 49, 55, 53, 49, 49, 56, 55, 53, 52, 57, 53, 53, 49,
        ],
        &[
            240, 169, 153, 188, 216, 85, 250, 28, 144, 146, 215, 209, 222, 34, 36, 53, 139, 31, 22, 15, 103, 141, 167,
            4, 180, 167, 183, 80, 182, 174, 73, 198,
        ],
    ),
    (
        "test_hmac_256",
        "1.2.840.113549.2.9",
        &[
            84, 105, 109, 101, 32, 49, 55, 53, 49, 49, 56, 53, 51, 51, 50, 51, 56, 52,
        ],
        &[
            69, 254, 166, 97, 86, 36, 191, 144, 166, 35, 186, 108, 7, 250, 13, 147, 24, 1, 238, 35, 198, 61, 136, 46,
            160, 96, 153, 14, 170, 81, 27, 26,
        ],
    ),
    (
        "test_rc2_128",
        "1.2.840.113549.3.2",
        &[
            84, 105, 109, 101, 32, 49, 55, 53, 49, 49, 56, 53, 50, 50, 57, 49, 54, 52,
        ],
        &[75, 60, 16, 204, 48, 60, 193, 106, 234, 229, 181, 63, 76, 75, 241, 44],
    ),
];

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
    assert_eq!(new_store.entries_len(), 2);
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
    //let entries = Map<String,>
    let keystore_with_aes_key = KeyStore::from_pkcs12(PBES2_KEYSTORE_AES_KEY, PASSWORD);

    assert!(&keystore_with_aes_key.is_ok());

    let keystore_with_aes_key = keystore_with_aes_key.unwrap();

    assert_eq!(13, keystore_with_aes_key.entries_len());

    for (name, oid, local_key_id, key) in TEST_ENTRIES {
        if let Some(entry) = keystore_with_aes_key.entry(name) {
            if let KeyStoreEntry::Secret(secret) = entry {
                assert_eq!(oid.to_string(), secret.key_type().to_oid().to_string());
                assert_eq!(*local_key_id, secret.local_key_id().as_ref());
                assert_eq!(*key, secret.key());
            } else {
                panic!("Wrong entry type {entry:?}");
            }
        } else {
            panic!("Entry {name} not found");
        }
    }
}

#[test]
fn test_keystore_read_write_copy() {
    let keystore_with_keys = KeyStore::from_pkcs12(PBES2_KEYSTORE_AES_KEY, PASSWORD);

    assert!(&keystore_with_keys.is_ok());

    if let Ok(keystore_with_keys) = keystore_with_keys {
        let store_data = keystore_with_keys.writer("welcome1").write().unwrap();

        let keystore_with_keys_copy = KeyStore::from_pkcs12(&store_data, "welcome1").unwrap();
        assert_eq!(13, keystore_with_keys_copy.entries_len());
    }
}

#[test]
fn test_keystore_create() {
    let mut keystore = KeyStore::new();
    let secret = Secret::builder(SecretKeyType::Aes).with_length(24).build().unwrap();
    keystore.add_entry("test", KeyStoreEntry::Secret(secret));
    let store_data = keystore.writer("welcome1").write().unwrap();

    let keystore_with_keys_copy = KeyStore::from_pkcs12(&store_data, "welcome1").unwrap();
    assert_eq!(1, keystore_with_keys_copy.entries_len());
}
