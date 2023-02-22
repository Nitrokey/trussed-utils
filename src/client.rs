use serde::{de::DeserializeOwned, Serialize};

use crate::EncryptedDataContainer;
use trussed::{
    client, try_syscall,
    types::{KeyId, Location, Message, PathBuf},
    Client, Error,
};

pub trait EncryptionUtil: Client + client::Chacha8Poly1305 + Sized {
    /// Stores data encrypted with ChaCha8Poly1305
    fn store_encrypted(
        &mut self,
        data: &[u8],
        ad: Option<&[u8]>,
        path: PathBuf,
        location: Location,
        encryption_key: KeyId,
    ) -> Result<(), Error> {
        let encrypted_container =
            EncryptedDataContainer::encrypt_message(self, data, ad, encryption_key)?;
        let encrypted_data: Message =
            trussed::cbor_serialize_bytes(&encrypted_container).map_err(|_| {
                error!("Failed to deserialize encrypted container");
                Error::CborError
            })?;
        try_syscall!(self.write_file(location, path, encrypted_data, None))?;
        Ok(())
    }
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
        data.decrypt_to_serialized(self, ad, encryption_key)
    }

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
