#![no_std]

use serde::{de::DeserializeOwned, Serialize};
use trussed::{
    config::MAX_MESSAGE_LENGTH,
    try_syscall,
    types::{KeyId, Location, Mechanism, Message, PathBuf},
    Bytes, Client, Error,
};

#[cfg(not(feature = "delog"))]
#[macro_use]
extern crate log;

#[cfg(feature = "delog")]
delog::generate_macros!();

const CHACHA_NONCE_LEN: usize = 12;
const POLY1305_TAG_LEN: usize = 16;
const MAX_ENCRYPTED_DATA_LEN: usize = MAX_MESSAGE_LENGTH - CHACHA_NONCE_LEN - POLY1305_TAG_LEN;

pub trait EncryptionUtil: Client + Sized {
    /// Stores data encrypted with ChaCha8Poly1305
    fn store_encrypted(
        &mut self,
        data: &[u8],
        path: PathBuf,
        location: Location,
        encryption_key: KeyId,
    ) -> Result<(), Error> {
        let mut encrypted_data = try_syscall!(self.encrypt(
            Mechanism::Chacha8Poly1305,
            encryption_key,
            data,
            &[],
            None
        ))?;
        assert_eq!(encrypted_data.nonce.len(), CHACHA_NONCE_LEN);
        assert_eq!(encrypted_data.tag.len(), POLY1305_TAG_LEN);
        encrypted_data
            .ciphertext
            .extend_from_slice(&encrypted_data.nonce)
            .map_err(|_| {
                warn!("Data is too large");
                Error::WrongMessageLength
            })?;
        encrypted_data
            .ciphertext
            .extend_from_slice(&encrypted_data.tag)
            .map_err(|_| {
                warn!("Data is too large");
                Error::WrongMessageLength
            })?;

        try_syscall!(self.write_file(location, path, encrypted_data.ciphertext, None))?;
        Ok(())
    }

    fn load_encrypted(
        &mut self,
        path: PathBuf,
        location: Location,
        encryption_key: KeyId,
    ) -> Result<Message, Error> {
        let data = try_syscall!(self.read_file(location, path))?.data;
        if data.len() < CHACHA_NONCE_LEN + POLY1305_TAG_LEN {
            warn!("Bad data to decrypt");
            return Err(Error::AeadError);
        }
        let (ciphertext, added) = data.split_at(data.len() - CHACHA_NONCE_LEN - POLY1305_TAG_LEN);
        let (nonce, tag) = added.split_at(CHACHA_NONCE_LEN);
        let plaintext = try_syscall!(self.decrypt(
            Mechanism::Chacha8Poly1305,
            encryption_key,
            ciphertext,
            &[],
            nonce,
            tag
        ))?
        .plaintext
        .ok_or_else(|| {
            warn!("No decrypted data");
            Error::AeadError
        })?;
        Ok(plaintext)
    }

    fn store_encrypted_struct<T: Serialize>(
        &mut self,
        data: &T,
        path: PathBuf,
        location: Location,
        encryption_key: KeyId,
    ) -> Result<(), Error> {
        let bytes: Bytes<MAX_ENCRYPTED_DATA_LEN> =
            trussed::cbor_serialize_bytes(data).map_err(|_err| {
                error!("Failed to serialize data: {:?}", _err);
                Error::CborError
            })?;
        self.store_encrypted(&bytes, path, location, encryption_key)
    }

    fn load_encrypted_struct<T: DeserializeOwned>(
        &mut self,
        path: PathBuf,
        location: Location,
        encryption_key: KeyId,
    ) -> Result<T, Error> {
        let data = self.load_encrypted(path, location, encryption_key)?;
        trussed::cbor_deserialize(&data).map_err(|_err| {
            error!("Failed to deserialize data: {:?}", _err);
            Error::CborError
        })
    }
}

impl<C: Client + Sized> EncryptionUtil for C {}
