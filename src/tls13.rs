//! GCM and ChaCha functions for TLS 1.3. For further documentation please refer to rust_symcrypt::gcm and symcrypt::chacha

use rust_symcrypt::block_ciphers::BlockCipherType;
use rust_symcrypt::chacha::{
    chacha20_poly1305_decrypt_in_place, chacha20_poly1305_encrypt_in_place,
};
use rust_symcrypt::gcm::GcmExpandedKey;
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, BorrowedPlainMessage, Iv, MessageDecrypter, MessageEncrypter, Nonce,
    OpaqueMessage, PlainMessage, Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::ConnectionTrafficSecrets;

const CHACHA_TAG_LENGTH: usize = 16;
const CHACHA_KEY_LENGTH: usize = 32;
const GCM_TAG_LENGTH: usize = 16;

/// ChaCha for TLS 1.3.

/// Tls13ChaCha impls [`Tls13AeadAlgorithm`]
pub struct Tls13ChaCha;

/// Tls13ChaCha20Poly1305 impls [`MessageEncrypter`] and [`MessageDecrypter`].
/// [`key`] is a ChaCha key and must be 32 bytes.
/// [`iv`] is an initialization vector that is needed to create the unique nonce.
pub struct Tls13ChaCha20Poly1305 {
    key: [u8; CHACHA_KEY_LENGTH],
    iv: Iv,
}

impl Tls13AeadAlgorithm for Tls13ChaCha {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        assert_eq!(key.as_ref().len(), CHACHA_KEY_LENGTH); // ChaCha key length must be 32 bytes.
        let mut chacha_key = [0u8; CHACHA_KEY_LENGTH];
        chacha_key[..CHACHA_KEY_LENGTH].copy_from_slice(key.as_ref());

        Box::new(Tls13ChaCha20Poly1305 {
            key: chacha_key,
            iv: iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        assert_eq!(key.as_ref().len(), CHACHA_KEY_LENGTH); // ChaCha key length must be 32 bytes.
        let mut chacha_key = [0u8; CHACHA_KEY_LENGTH];
        chacha_key[..CHACHA_KEY_LENGTH].copy_from_slice(key.as_ref());

        Box::new(Tls13ChaCha20Poly1305 {
            key: chacha_key,
            iv: iv,
        })
    }

    fn key_len(&self) -> usize {
        CHACHA_KEY_LENGTH // ChaCha key must be 32 bytes.
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

/// [`MessageEncrypter`] for ChaCha 1.3
/// the [`payload`] field that comes from the [`BorrowedPlainMessage`] is structured to include the message which is an arbitrary length,
/// an encoding type that is 1 byte and then finally the tag which is 16 bytes.
/// ex : [1, 2, 3, 5, 6, 7, 8, 9, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                       ^   ^  ^                                                   ^
///            Message (N bytes)   Encoding (1 Byte)              Tag (16 bytes)
impl MessageEncrypter for Tls13ChaCha20Poly1305 {
    fn encrypt(&self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, rustls::Error> {
        // Adding the size of message, the tag and encoding type to the capacity of payload vector.
        let total_len = msg.payload.len() + 1 + CHACHA_TAG_LENGTH;
        let mut payload = Vec::with_capacity(total_len);

        // Construct payload.
        payload.extend_from_slice(msg.payload);
        payload.push(msg.typ.get_u8());

        // Set up needed parameters for ChaCha encrypt.
        let nonce = Nonce::new(&self.iv, seq);
        let auth_data = make_tls13_aad(total_len);
        let mut tag = [0u8; CHACHA_TAG_LENGTH];

        // Encrypting the payload in place. +1 is added to account for encoding type that must also be encrypted.
        match chacha20_poly1305_encrypt_in_place(
            &self.key,
            &nonce.0,
            &auth_data,
            &mut payload[..msg.payload.len() + 1],
            &mut tag,
        ) {
            Ok(_) => {
                payload.extend_from_slice(&tag); // Add tag to the end of the payload.
                Ok(OpaqueMessage::new(
                    rustls::ContentType::ApplicationData,
                    rustls::ProtocolVersion::TLSv1_3, // !TODO: ask rustls why they have 1_2 rather than 1_3 here.
                    payload,
                ))
            }
            Err(symcrypt_error) => {
                let custom_error_message = format!(
                    "SymCryptError: {}",
                    symcrypt_error.to_string() // Using general error to propagate the SymCrypt error back to the caller
                );
                return Err(rustls::Error::General(custom_error_message));
            }
        }
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + CHACHA_TAG_LENGTH
    }
}

/// [`MessageDecrypter`] for ChaCha 1.3
/// the [`payload`] field that comes from the [`OpaqueMessage`] is structured to include the message which is an arbitrary length,
/// an encoding type that is 1 byte and then finally the tag which is 16 bytes.
/// ex : [1, 2, 3, 5, 6, 7, 8, 9, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                       ^   ^  ^                                                   ^
///            Message (N bytes)   Encoding (1 Byte)              Tag (16 bytes)
impl MessageDecrypter for Tls13ChaCha20Poly1305 {
    fn decrypt(&self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, rustls::Error> {
        let mut payload = msg.payload_mut();
        let payload_len = payload.len(); // This length includes the message, encoding, and tag.

        // Ensure that the length is over 16 bytes or there is a decryption error.
        if payload_len < CHACHA_TAG_LENGTH {
            return Err(rustls::Error::DecryptError);
        }
        let message_length = payload_len - CHACHA_TAG_LENGTH; // getting message length, this includes the message length and the encoding type.

        // Set up needed parameters for ChaCha decrypt
        let nonce = Nonce::new(&self.iv, seq);
        let auth_data = make_tls13_aad(payload_len); // The total message including tag and encoding byte must be used for auth data.
        let mut tag = [0u8; GCM_TAG_LENGTH];
        tag.copy_from_slice(&payload[message_length..]);

        // Decrypting the payload in place, there is no +1 here since [`message_length`] accounts for the extra byte for encoding type.
        match chacha20_poly1305_decrypt_in_place(
            &self.key,
            &nonce.0,
            &auth_data,
            &mut payload[..message_length],
            &tag,
        ) {
            Ok(_) => {
                payload.truncate(message_length);
                msg.into_tls13_unpadded_message() // This removes the optional padding of zero bytes.
            }
            Err(symcrypt_error) => {
                let custom_error_message = format!(
                    "SymCryptError: {}",
                    symcrypt_error.to_string() // Using general error to propagate the SymCrypt error back to the caller
                );
                return Err(rustls::Error::General(custom_error_message));
            }
        }
    }
}

/// GCM for TLS 1.3

/// Tls13Gcm impls [`Tls13AeadAlgorithm`].
///
/// [`algo_type`] represents either GCM128 or GCM256 which corresponds to a 16 and 32 byte key respectively.
pub struct Tls13Gcm {
    algo_type: AesGcm,
}

/// Algo types for GCM TLS 1.3 and TLS 1.2
pub enum AesGcm {
    Aes128Gcm,
    Aes256Gcm,
}

impl AesGcm {
    pub fn key_size(&self) -> usize {
        match self {
            AesGcm::Aes128Gcm => 16,
            AesGcm::Aes256Gcm => 32,
        }
    }
}

/// Tls13GcmState impls [`MessageEncrypter`] and [`MessageDecrypter`]
///
/// [`key`] is a rust-symcrypt::GcmExpandedKey that has expands the provided key
/// [`iv`] is an initialization vector that is needed to create the unique nonce.
pub struct Tls13GcmState {
    key: GcmExpandedKey,
    iv: Iv,
}

impl Tls13AeadAlgorithm for Tls13Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        // Unwrapping here, in the scenarios that GcmExpandKey would fail should result in a panic, ie: Not enough memory.
        Box::new(Tls13GcmState {
            key: GcmExpandedKey::new(key.as_ref(), BlockCipherType::AesBlock).unwrap(),
            iv: iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        // Unwrapping here, in the scenarios that GcmExpandKey would fail should result in a panic, ie: Not enough memory.
        Box::new(Tls13GcmState {
            key: GcmExpandedKey::new(key.as_ref(), BlockCipherType::AesBlock).unwrap(),
            iv: iv,
        })
    }

    fn key_len(&self) -> usize {
        self.algo_type.key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        match self.key_len() {
            16 => Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv }),
            32 => Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv }),
        }
    }
}

/// [`MessageEncrypter`] for GCM 1.3
/// the [`payload`] field that comes from the [`BorrowedPlainMessage`] is structured to include the message which is an arbitrary length,
/// an encoding type that is 1 byte and then finally the tag which is 16 bytes.
/// ex : [1, 2, 3, 5, 6, 7, 8, 9, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                       ^   ^  ^                                                   ^
///            Message (N bytes)   Encoding (1 Byte)              Tag (16 bytes)
impl MessageEncrypter for Tls13GcmState {
    fn encrypt(&self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, rustls::Error> {
        // Adding the size of the tag and encoding type to the capacity of payload vector.
        let total_len = msg.payload.len() + 1 + GCM_TAG_LENGTH;
        let mut payload = Vec::with_capacity(total_len);

        // Construct payload
        payload.extend_from_slice(msg.payload);
        payload.push(msg.typ.get_u8());

        // Set up needed parameters for Gcm Encrypt
        let mut tag = [0u8; GCM_TAG_LENGTH];
        let nonce = Nonce::new(&self.iv, seq);
        let auth_data = make_tls13_aad(total_len);

        // Encrypting the payload in place, +1 is added to account for the encoding type. This call cannot fail.
        self.key.encrypt_in_place(
            &nonce.0,
            &auth_data,
            &mut payload[..msg.payload.len() + 1],
            &mut tag,
        );

        payload.extend_from_slice(&tag);
        Ok(OpaqueMessage::new(
            rustls::ContentType::ApplicationData,
            rustls::ProtocolVersion::TLSv1_3, // TODO: ask rustls why they have 1_2 rather than 1_3 here
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + GCM_TAG_LENGTH
    }
}

/// [`MessageDecrypter`] for GCM 1.3
/// the [`payload`] field that comes from the [`OpaqueMessage`] is structured to include the message which is an arbitrary length,
/// an encoding type that is 1 byte. After the encoding byte there can be a padding of 0 or more zero bytes, and finally the tag which is 16 bytes.
/// ex : [1, 2, 3, 5, 6, 7, 8, 9, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                       ^   ^  ^                                                   ^
///            Message (N bytes)   Encoding (1 Byte)              Tag (16 bytes)
impl MessageDecrypter for Tls13GcmState {
    fn decrypt(&self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, rustls::Error> {
        let mut payload = msg.payload_mut();
        let payload_len = payload.len(); // This length includes the message, encoding, and tag.

        if payload_len < GCM_TAG_LENGTH {
            return Err(rustls::Error::DecryptError);
        }
        let message_length = payload_len - GCM_TAG_LENGTH; // This includes the message length and the encoding type.

        // Set up needed parameters for GCM decrypt.
        let nonce = Nonce::new(&self.iv, seq);
        let auth_data = make_tls13_aad(payload_len); // The whole message, including encoding type and tag should be used.
        let mut tag = [0u8; GCM_TAG_LENGTH];
        tag.copy_from_slice(&payload[payload_len - GCM_TAG_LENGTH..]);

        // Decrypting the payload in place, there is no +1 here since [`message_length`] accounts for the extra byte for encoding type.
        match self
            .key
            .decrypt_in_place(&nonce.0, &auth_data, &mut payload[..message_length], &tag)
        {
            Ok(()) => {
                payload.truncate(message_length);
                msg.into_tls13_unpadded_message() // This removes the optional padding of zero bytes.
            }
            Err(symcrypt_error) => {
                let custom_error_message = format!(
                    "SymCryptError: {}",
                    symcrypt_error.to_string() // Using general error to propagate the SymCrypt error back to the caller
                );
                return Err(rustls::Error::General(custom_error_message));
            }
        }
    }
}
