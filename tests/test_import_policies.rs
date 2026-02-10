use p12_keystore::{KeyStore, KeyStoreEntry, Pkcs12ImportPolicy};

const PASSWORD: &str = "";
const KEYSTORE: &[u8] = include_bytes!("assets/clear_twocert.p12");

/// Test Strict policy: only imports keys that have matching certificates
#[test]
fn test_strict_policy() {
    let keystore = KeyStore::from_pkcs12(KEYSTORE, PASSWORD, Pkcs12ImportPolicy::Strict).unwrap();

    // Strict policy should import private key chains with certificates
    assert!(keystore.entries_len() > 0);

    // All private key chains should have at least one certificate
    for (_, entry) in keystore.entries() {
        if let KeyStoreEntry::PrivateKeyChain(chain) = entry {
            assert!(
                !chain.certs().is_empty(),
                "Strict policy: PrivateKeyChain should have certificates"
            );
        }
    }
}

/// Test Relaxed policy: imports keys even without matching certificates
#[test]
fn test_relaxed_policy() {
    let keystore = KeyStore::from_pkcs12(KEYSTORE, PASSWORD, Pkcs12ImportPolicy::Relaxed).unwrap();

    // Relaxed policy should import everything
    assert!(keystore.entries_len() > 0);

    // Keys with matching certificates should have cert chains
    // Keys without matching certificates should have empty cert chains
    let mut has_full_chain = false;

    for (_, entry) in keystore.entries() {
        if let KeyStoreEntry::PrivateKeyChain(chain) = entry {
            if !chain.certs().is_empty() {
                has_full_chain = true;
            }
        }
    }

    // For normal keystores, we should have chains with certificates
    assert!(
        has_full_chain,
        "Relaxed policy: should have at least one chain with certificates"
    );
}

/// Test Raw policy: no linking, all entries imported independently
#[test]
fn test_raw_policy() {
    let keystore = KeyStore::from_pkcs12(KEYSTORE, PASSWORD, Pkcs12ImportPolicy::Raw).unwrap();

    // Raw policy should import everything
    assert!(keystore.entries_len() > 0);

    // All private key chains should have NO certificates (no linking performed)
    // All certificates should be independent entries
    let mut key_count = 0;
    let mut cert_count = 0;

    for (_, entry) in keystore.entries() {
        match entry {
            KeyStoreEntry::PrivateKeyChain(chain) => {
                key_count += 1;
                assert!(
                    chain.certs().is_empty(),
                    "Raw policy: PrivateKeyChain should have no certificates (no linking)"
                );
            }
            KeyStoreEntry::Certificate(_) => {
                cert_count += 1;
            }
            _ => {}
        }
    }

    assert_eq!(key_count, 1, "Raw policy: should have imported private keys");
    assert_eq!(
        cert_count, 2,
        "Raw policy: should have imported certificates as independent entries"
    );
}
