use trussed::{
    client::{Chacha8Poly1305, CryptoClient},
    syscall,
    types::{Location, PathBuf},
    virt::with_ram_client,
    Error,
};
use trussed_utils::EncryptionUtil;

const DATA: &[u8] = b"Some random data";

#[test_log::test]
fn encryption_bad_key() {
    with_ram_client("utils test", |mut client| {
        let key = syscall!(client.generate_chacha8poly1305_key(Location::Volatile)).key;
        syscall!(client.delete(key));
        assert_eq!(
            client.store_encrypted(DATA, PathBuf::from("path"), Location::Volatile, key),
            Err(Error::NoSuchKey)
        );
    });
}

#[test_log::test]
fn decryption_bad_key() {
    with_ram_client("utils test", |mut client| {
        let key = syscall!(client.generate_chacha8poly1305_key(Location::Volatile)).key;
        client
            .store_encrypted(DATA, PathBuf::from("path"), Location::Volatile, key)
            .unwrap();
        syscall!(client.delete(key));
        assert_eq!(
            client.load_encrypted(PathBuf::from("path"), Location::Volatile, key),
            Err(Error::NoSuchKey)
        );
    });
}

#[test_log::test]
fn encryption_decryption() {
    with_ram_client("utils test", |mut client| {
        let key = syscall!(client.generate_chacha8poly1305_key(Location::Volatile)).key;
        client
            .store_encrypted(DATA, PathBuf::from("path"), Location::Volatile, key)
            .unwrap();
        assert_eq!(
            client
                .load_encrypted(PathBuf::from("path"), Location::Volatile, key)
                .unwrap(),
            DATA
        );
    });
}
