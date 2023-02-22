use heapless_bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::Serialize;
use trussed::error::{Error, Result};
use trussed::types::{KeyId, Message};
use trussed::{cbor_deserialize, cbor_serialize, try_syscall};

/// Universal AEAD encrypted data container, using CBOR and Chacha8Poly1305
///
/// Encryption is realized by serializing the object using CBOR, then encrypting it using Chacha8Poly1305,
/// storing related crypto data, namely nonce and tag, and finally serializing the latter,
/// again using CBOR.
///
/// For the plaintext of size 48 bytes, the resulting container size is 87 bytes,
/// including the 28 bytes of cryptographic data overhead, and leaving 11 bytes
/// as the CBOR serialization overhead.
///
/// Decryption operation is done the same way as its counterpart, but backwards.
/// The serialized Encrypted Data Container in bytes is first deserialized, making a EDC instance,
/// and afterwards the decryption operation in Trussed is called, resulting in a original serialized
/// object, which is then deserialized to a proper instance.
///
/// CBOR was chosen as the serialization format due to its simplicity and extensibility.
/// If that is a requirement, more space efficient and faster would be postcard. Be advised however,
/// that it's format changes between major revisions (as expected with semver versioning).
///
/// This type has implemented bidirectional serialization to trussed Message object.
///
/// Showing the processing paths graphically:
///
/// T -> \[u8\]: object -> CBOR serialization -> EncryptedDataContainer encryption  -> CBOR serialization -> serialized EncryptedDataContainer
///
/// \[u8\] -> T: serialized EncryptedDataContainer -> CBOR deserialization -> EncryptedDataContainer decryption -> CBOR deserialization -> object
///
/// Note: to decrease the CBOR overhead it might be useful to rename the serialized object fields for
/// the serialization purposes. Use the `#[serde(rename = "A")]` attribute.
///
/// The minimum buffer size for the serialization operation of a single encrypted+serialized credential
/// should be about 256 bytes (the current maximum packet length) + CBOR overhead (field names and map encoding) + encryption overhead (12 bytes nonce + 16 bytes tag).
/// The extra bytes could be used in the future, when operating on the password-extended credentials.
///
/// Usage example:
/// ```
/// # use trussed::Client;
/// # use serde::Serialize;
/// # use trussed::client::Chacha8Poly1305;
/// # use trussed::types::{KeyId, Message};
/// # use trussed_utils::EncryptedDataContainer;
/// fn encrypt_unit<O: Serialize, T: Client + Chacha8Poly1305>(trussed: &mut T, obj: &O, ek: KeyId) -> Message {
///    let data = EncryptedDataContainer::from_struct(trussed, obj, None, ek).unwrap();
///    let data_serialized: Message = data.try_into().unwrap();
///    data_serialized
/// }
/// ```
/// Future work and extensions:
/// - Generalize over serialization method
/// - Generalize buffer size (currently buffer is based on the Message type)
/// - Investigate postcard structure extensibility, as a means for smaller overhead for serialization
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct EncryptedDataContainer {
    /// The ciphertext. 1024 bytes maximum. Reusing trussed::types::Message.
    #[serde(rename = "D")]
    data: trussed::types::Message,
    #[serde(rename = "T")]
    tag: ContainerTag,
    #[serde(rename = "N")]
    nonce: ContainerNonce,
}

type ContainerTag = Bytes<16>;
type ContainerNonce = Bytes<12>;

impl TryFrom<&[u8]> for EncryptedDataContainer {
    type Error = Error;

    /// Create an instance from this serialized Encrypted Data Container
    fn try_from(value: &[u8]) -> Result<Self> {
        cbor_deserialize(value).map_err(|_| Error::CborError)
    }
}

impl TryFrom<EncryptedDataContainer> for Message {
    type Error = Error;

    /// Try to serialize EncryptedDataContainer to Bytes
    fn try_from(value: EncryptedDataContainer) -> Result<Self> {
        Message::try_from(|buf| {
            cbor_serialize(&value, buf)
                .map(|s| s.len())
                .map_err(|_| Error::CborError)
        })
    }
}

impl EncryptedDataContainer {
    /// Decrypt given Bytes and return original object instance
    pub fn decrypt_bytes_to_struct<T, O>(
        trussed: &mut T,
        ser_encrypted: Message,
        encryption_key: KeyId,
    ) -> Result<O>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        O: DeserializeOwned,
    {
        let deserialized_container: EncryptedDataContainer =
            cbor_deserialize(&ser_encrypted).map_err(|_| Error::CborError)?;

        deserialized_container.decrypt_to_struct(trussed, None, encryption_key)
    }

    /// Create Encrypted Data Container from the given object
    pub fn from_struct<T, O>(
        trussed: &mut T,
        obj: &O,
        associated_data: Option<&[u8]>,
        encryption_key: KeyId,
    ) -> Result<EncryptedDataContainer>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        O: Serialize,
    {
        let message = Message::try_from(|buf| {
            cbor_serialize(&obj, buf)
                .map(|s| s.len())
                .map_err(|_| Error::CborError)
        })
        .map_err(|_| Error::CborError)?;
        debug!("Plaintext size: {}", message.len());
        Self::encrypt(trussed, &message, associated_data, encryption_key)
    }

    /// Encrypt given Bytes object, and return an Encrypted Data Container
    pub fn encrypt<T>(
        trussed: &mut T,
        message: &[u8],
        associated_data: Option<&[u8]>,
        encryption_key: KeyId,
    ) -> Result<EncryptedDataContainer>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
    {
        #[cfg(no_encrypted_container)]
        {
            // Skipping error handling, as this feature is only for the debugging purposes
            return Ok(EncryptedDataContainer {
                data: Message::from_slice(&message).unwrap(),
                nonce: Default::default(),
                tag: Default::default(),
                // nonce: ShortData::from_slice(&[12u8, 12]).unwrap(),
                // tag: ShortData::from_slice(&[16u8, 16]).unwrap(),
            });
        }

        // nonce is provided internally via internal per-key counter, hence not passed here
        let encryption_results = try_syscall!(trussed.encrypt_chacha8poly1305(
            encryption_key,
            message,
            associated_data.unwrap_or_default(),
            None
        ))?;

        let encrypted_serialized_credential = EncryptedDataContainer {
            data: encryption_results.ciphertext,
            nonce: encryption_results.nonce.try_convert_into().unwrap(), // should always be 12 bytes
            tag: encryption_results.tag.try_convert_into().unwrap(), // should always be 16 bytes
        };
        Ok(encrypted_serialized_credential)
    }

    /// Decrypt the content of this Encrypted Data Instance, and deserialize to the original object
    pub fn decrypt_to_struct<T, O>(
        &self,
        trussed: &mut T,
        associated_data: Option<&[u8]>,
        encryption_key: KeyId,
    ) -> Result<O>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        O: DeserializeOwned,
    {
        let message = self.decrypt(trussed, associated_data, encryption_key)?;
        cbor_deserialize(&message).map_err(|_| Error::CborError)
    }

    /// Decrypt the content of this Encrypted Data Instance, and return the original serialized object
    pub fn decrypt<T>(
        &self,
        trussed: &mut T,
        associated_data: Option<&[u8]>,
        encryption_key: KeyId,
    ) -> Result<Message>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
    {
        #[cfg(no_encrypted_container)]
        {
            // Skipping error handling, as this feature is only for the debugging purposes
            return Ok(Message::from_slice(&self.data).unwrap());
        }

        let serialized = try_syscall!(trussed.decrypt_chacha8poly1305(
            encryption_key,
            &self.data,
            associated_data.unwrap_or_default(),
            &self.nonce,
            &self.tag
        ))?
        .plaintext
        .ok_or(Error::AeadError)?;

        Ok(serialized)
    }
}
