#![no_std]

use trussed::{
    try_syscall,
    types::{KeyId, Location, Mechanism, Message, PathBuf},
    Client, Error,
};

#[cfg(not(feature = "delog"))]
#[macro_use]
extern crate log;

#[cfg(feature = "delog")]
delog::generate_macros!();

const CHACHA_NONCE_LEN: usize = 12;
const POLY1305_TAG_LEN: usize = 16;

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
}

impl<C: Client + Sized> EncryptionUtil for C {}
