use quickcheck::quickcheck;
use std::panic::catch_unwind;
use trussed::{
    client::{Chacha8Poly1305, CryptoClient},
    config::MAX_MESSAGE_LENGTH,
    syscall,
    types::{Location, PathBuf},
    virt::with_ram_client,
    Error,
};
use trussed_utils::EncryptionUtil;

const DATA: &[u8] = b"Some random data";
const AD: Option<&[u8]> = Some(b"Some random associated data");

#[test_log::test]
fn encryption_bad_key() {
    with_ram_client("utils test", |mut client| {
        let key = syscall!(client.generate_chacha8poly1305_key(Location::Volatile)).key;
        syscall!(client.delete(key));
        assert_eq!(
            client.store_encrypted(DATA, AD, PathBuf::from("path"), Location::Volatile, key),
            Err(Error::NoSuchKey)
        );
    });
}

#[test_log::test]
fn decryption_bad_key() {
    with_ram_client("utils test", |mut client| {
        let key = syscall!(client.generate_chacha8poly1305_key(Location::Volatile)).key;
        client
            .store_encrypted(DATA, AD, PathBuf::from("path"), Location::Volatile, key)
            .unwrap();
        syscall!(client.delete(key));
        assert_eq!(
            client.load_encrypted(PathBuf::from("path"), AD, Location::Volatile, key),
            Err(Error::NoSuchKey)
        );
    });
}

#[test_log::test]
fn encryption_decryption() {
    with_ram_client("utils test", |mut client| {
        let key = syscall!(client.generate_chacha8poly1305_key(Location::Volatile)).key;
        client
            .store_encrypted(DATA, AD, PathBuf::from("path"), Location::Volatile, key)
            .unwrap();
        assert_eq!(
            client
                .load_encrypted(PathBuf::from("path"), AD, Location::Volatile, key)
                .unwrap(),
            DATA
        );
    });
}

fn int_location(i: u8) -> Location {
    match i % 3 {
        0 => Location::Volatile,
        1 => Location::External,
        2 => Location::Internal,
        _ => unimplemented!(),
    }
}

fn arbitrary_data_inner(
    data: &[u8],
    location_store: Location,
    location_load: Location,
    good_key_store: bool,
    good_key_load: bool,
    good_ad_load: bool,
) -> bool {
    with_ram_client("utils tests", |mut client| {
        let good_key = syscall!(client.generate_chacha8poly1305_key(Location::Volatile)).key;
        let bad_key = syscall!(client.generate_chacha8poly1305_key(Location::Volatile)).key;
        syscall!(client.delete(bad_key));
        match good_key_store {
            false => {
                assert_eq!(
                    client.store_encrypted(
                        data,
                        AD,
                        PathBuf::from("path"),
                        location_store,
                        bad_key
                    ),
                    Err(Error::NoSuchKey)
                );
            }
            true => client
                .store_encrypted(data, AD, PathBuf::from("path"), location_store, good_key)
                .unwrap(),
        }
        let ad = match good_ad_load {
            true => AD,
            false => None,
        };
        match good_key_load {
            false => assert_eq!(
                client.load_encrypted(PathBuf::from("path"), ad, location_load, bad_key),
                if location_load == location_store && good_key_store {
                    Err(Error::NoSuchKey)
                } else {
                    Err(Error::FilesystemReadFailure)
                }
            ),
            true => {
                let res = client.load_encrypted(PathBuf::from("path"), ad, location_load, good_key);
                if location_load == location_store {
                    if good_key_store && good_ad_load {
                        assert_eq!(res.unwrap(), data);
                    } else if good_key_store && !good_ad_load {
                        assert_eq!(res, Err(Error::AeadError))
                    } else {
                        assert_eq!(res, Err(Error::FilesystemReadFailure))
                    }
                } else {
                    assert_eq!(res, Err(Error::FilesystemReadFailure))
                }
            }
        }
        true
    })
}

quickcheck! {
    fn arbitrary_data(
        data: Vec<u8>,
        location_store: u8,
        location_load: u8,
        good_key_store: bool,
        good_key_load: bool,
        good_ad_load: bool
    ) -> bool {
        let location_store = int_location(location_store);
        let location_load = int_location(location_load);
        let data = &data[..MAX_MESSAGE_LENGTH.min(data.len())];
        catch_unwind(||{
            arbitrary_data_inner(
                data,
                location_store,
                location_load,
                good_key_store,
                good_key_load,
                good_ad_load,
            )
        }).is_ok()
    }
}
