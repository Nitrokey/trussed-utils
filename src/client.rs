use serde::{de::DeserializeOwned, Serialize};

use crate::EncryptedDataContainer;
use trussed::{
    client, try_syscall,
    types::{KeyId, Location, Message, PathBuf},
    Client, Error,
};

/// Helper trait to encrypt data
///
/// This trait is implemented for all trussed clients.
///
/// Data can be either
/// - bytes: use [`store_encrypted`](EncryptionUtil::store_encrypted) and [`load_encrypted`](EncryptionUtil::load_encrypted)
/// - any serde-compatible structure: use [`store_encrypted_struct`](EncryptionUtil::store_encrypted_struct) and [`load_encrypted_struct`](EncryptionUtil::load_encrypted_struct)
///
/// ## Encrypting bytes
///
/// ```rust
/// # use trussed::{virt::with_ram_client,syscall,types::{PathBuf,Location},client::Chacha8Poly1305};
/// # use trussed_utils::EncryptionUtil;
/// # with_ram_client("utils test", |mut client| {
/// # let key = syscall!(client.generate_chacha8poly1305_key(Location::Volatile)).key;
/// client.store_encrypted(b"data", Some(b"ad"), PathBuf::from("path"), Location::Volatile, key)?;
/// assert_eq!(
///     client.load_encrypted(Some(b"ad"), PathBuf::from("path"), Location::Volatile, key)?,
///     b"data",
/// );
/// # Ok::<(),trussed::Error>(())
/// # });
/// ```
///
/// ## Encrypting structured data
///
/// ```rust
/// # use trussed::{virt::with_ram_client,syscall,types::{PathBuf,Location},client::Chacha8Poly1305};
/// # use trussed_utils::EncryptionUtil;
/// # use serde::{Serialize, Deserialize};
/// # with_ram_client("utils test", |mut client| {
/// # let key = syscall!(client.generate_chacha8poly1305_key(Location::Volatile)).key;
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// struct Data {
///     a: bool,
///     b: u8,
/// }
/// client.store_encrypted_struct(
///     &Data {a: true, b: 1},
///     Some(b"ad"),
///     PathBuf::from("path"),
///     Location::Volatile,
///     key
/// )?;
/// assert_eq!(
///     Data {a: true, b: 1},
///     client.load_encrypted_struct(
///         Some(b"ad"),
///         PathBuf::from("path"),
///         Location::Volatile,
///         key
///     )?,
/// );
/// # Ok::<(),trussed::Error>(())
/// # });
/// ```
pub trait EncryptionUtil: Client + client::Chacha8Poly1305 + Sized {
    /// Store byte encrypted with ChaCha8Poly1305
    ///
    /// The data must then be loaded with [`load_encrypted`](EncryptionUtil::load_encrypted)
    fn store_encrypted(
        &mut self,
        data: &[u8],
        ad: Option<&[u8]>,
        path: PathBuf,
        location: Location,
        encryption_key: KeyId,
    ) -> Result<(), Error> {
        let encrypted_container = EncryptedDataContainer::encrypt(self, data, ad, encryption_key)?;
        let encrypted_data: Message =
            trussed::cbor_serialize_bytes(&encrypted_container).map_err(|_| {
                error!("Failed to deserialize encrypted container");
                Error::CborError
            })?;
        try_syscall!(self.write_file(location, path, encrypted_data, None))?;
        Ok(())
    }

    /// Load bytes that were encrypted with [`store_encrypted`](EncryptionUtil::store_encrypted)
    fn load_encrypted(
        &mut self,
        ad: Option<&[u8]>,
        path: PathBuf,
        location: Location,
        encryption_key: KeyId,
    ) -> Result<Message, Error> {
        let data: EncryptedDataContainer =
            trussed::cbor_deserialize(&try_syscall!(self.read_file(location, path))?.data)
                .map_err(|_| {
                    error!("Failed to deserialize encrypted container");
                    Error::CborError
                })?;
        data.decrypt(self, ad, encryption_key)
    }

    /// Store structured data encrypted with ChaCha8Poly1305
    ///
    /// The data must then be loaded with [`load_encrypted_struct`](EncryptionUtil::load_encrypted_struct)
    fn store_encrypted_struct<T: Serialize>(
        &mut self,
        data: &T,
        ad: Option<&[u8]>,
        path: PathBuf,
        location: Location,
        encryption_key: KeyId,
    ) -> Result<(), Error> {
        let bytes: Message = trussed::cbor_serialize_bytes(data).map_err(|_err| {
            error!("Failed to serialize data: {:?}", _err);
            Error::CborError
        })?;
        self.store_encrypted(&bytes, ad, path, location, encryption_key)
    }

    /// Load structured data that was encrypted with [`store_encrypted_struct`](EncryptionUtil::store_encrypted_struct)
    fn load_encrypted_struct<T: DeserializeOwned>(
        &mut self,
        ad: Option<&[u8]>,
        path: PathBuf,
        location: Location,
        encryption_key: KeyId,
    ) -> Result<T, Error> {
        let data = self.load_encrypted(ad, path, location, encryption_key)?;
        trussed::cbor_deserialize(&data).map_err(|_err| {
            error!("Failed to deserialize data: {:?}", _err);
            Error::CborError
        })
    }
}

impl<C: Client + client::Chacha8Poly1305> EncryptionUtil for C {}
