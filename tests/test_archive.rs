use p12_keystore::{KeyStore, KeyStoreEntry, Pkcs12Archive, Pkcs12ImportPolicy, PrivateKeyChain};

const FIXTURE: &[u8] = include_bytes!("assets/clear_twocert.p12");

fn fixture_chain() -> PrivateKeyChain {
    let store = KeyStore::from_pkcs12(FIXTURE, "", Pkcs12ImportPolicy::Strict).unwrap();
    store.private_key_chain().unwrap().1.clone()
}

fn write(chain: PrivateKeyChain, alias: &str, password: &str) -> Vec<u8> {
    let mut store = KeyStore::new();
    store.add_entry(alias, KeyStoreEntry::PrivateKeyChain(chain));
    store
        .writer(password)
        .encryption_iterations(100)
        .mac_iterations(100)
        .write()
        .unwrap()
}

#[test]
fn archive_preserves_duplicate_and_unrelated_certificate_bags() {
    let original = Pkcs12Archive::from_pkcs12(FIXTURE, "").unwrap();
    let chain = fixture_chain();
    let leaf = chain.certs()[0].clone();
    // This issuer is unrelated to the self-signed leaf; include it twice.
    let other = original.certs.iter().find(|bag| bag.cert != leaf).unwrap().cert.clone();
    let chain = PrivateKeyChain::new(
        chain.local_key_id().clone(),
        chain.key().clone(),
        [leaf.clone(), other.clone(), other.clone()],
    );
    let bytes = write(chain, leaf.subject(), "password");
    let archive = Pkcs12Archive::from_pkcs12(&bytes, "password").unwrap();
    assert_eq!(archive.keys.len(), 1);
    assert_eq!(archive.certs.len(), 3);
    assert_eq!(archive.certs[0].cert, leaf);
    assert_eq!(archive.certs[1].cert, other);
    assert_eq!(archive.certs[2].cert, other);
    assert_eq!(archive.keys[0].friendly_name, archive.certs[0].friendly_name);
    assert_eq!(
        archive.keys[0].local_key_id.as_ref().unwrap().as_ref(),
        archive.certs[0].local_key_id.as_ref().unwrap()
    );
    assert!(Pkcs12Archive::from_pkcs12(&bytes, "wrong password").is_err());
}

#[test]
fn raw_import_preserves_keys_and_certificates_with_colliding_aliases() {
    let chain = fixture_chain();
    let leaf = chain.certs()[0].clone();
    let alias = leaf.subject().to_owned();
    let chain = PrivateKeyChain::new(
        chain.local_key_id().clone(),
        chain.key().clone(),
        [leaf.clone(), leaf.clone()],
    );
    let bytes = write(chain, &alias, "");
    let raw = KeyStore::from_pkcs12(&bytes, "", Pkcs12ImportPolicy::Raw).unwrap();
    assert_eq!(raw.entries_len(), 3);
    assert!(matches!(raw.entry(&alias), Some(KeyStoreEntry::PrivateKeyChain(_))));
    for suffix in [2, 3] {
        assert!(matches!(
            raw.entry(&format!("{alias}#{suffix}")),
            Some(KeyStoreEntry::Certificate(_))
        ));
    }
    assert_eq!(raw.private_key_chain().unwrap().1.certs().len(), 0);
}

#[test]
fn archive_rejects_bad_passwords_and_modified_macs() {
    let bytes = write(fixture_chain(), "identity", "correct");
    assert!(Pkcs12Archive::from_pkcs12(&bytes, "correct").is_ok());
    assert!(Pkcs12Archive::from_pkcs12(&bytes, "wrong").is_err());
    let mut damaged = bytes;
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    assert!(Pkcs12Archive::from_pkcs12(&damaged, "correct").is_err());
}
