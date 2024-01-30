//! GCM and ChaCha functions for TLS 1.2. For further documentation please refer to rust_symcrypt::gcm and symcrypt::chacha

use crate::tls13::AesGcm;
use symcrypt::block_ciphers::BlockCipherType;
use symcrypt::chacha::{
    chacha20_poly1305_decrypt_in_place, chacha20_poly1305_encrypt_in_place,
};
use symcrypt::gcm::GcmExpandedKey;
use rustls::crypto::cipher::{
    make_tls12_aad, AeadKey, BorrowedPlainMessage, Iv, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, Nonce, BorrowedOpaqueMessage, PlainMessage, OpaqueMessage, Tls12AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::ConnectionTrafficSecrets;
use rustls::Error;

const CHACHA_TAG_LENGTH: usize = 16;
const CHAHCA_NONCE_LENGTH: usize = 12;
const CHACHA_KEY_LENGTH: usize = 32;
const GCM_FULL_NONCE_LENGTH: usize = 12;
const GCM_EXPLICIT_NONCE_LENGTH: usize = 8;
const GCM_IMPLICIT_NONCE_LENGTH: usize = 4;
const GCM_TAG_LENGTH: usize = 16;

/// ChaCha for TLS 1.2
///
/// [`Tls12ChaCha`] impls [`Tls12AeadAlgorithm`].
pub struct Tls12ChaCha;

/// [`TLs12ChaCha20Poly1305`] impls [`MessageEncrypter`] and [`MessageDecrypter`]
/// [`key`] is a ChaCha key and must be 32 bytes long.
/// [`iv`] is an initialization vector that is needed to create the unique nonce.
pub struct Tls12ChaCha20Poly1305 {
    key: [u8; CHACHA_KEY_LENGTH],
    iv: Iv,
}

impl Tls12AeadAlgorithm for Tls12ChaCha {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        assert_eq!(key.as_ref().len(), CHACHA_KEY_LENGTH); // ChaCha key length must be 32 bytes.

        let mut chacha_key = [0u8; CHACHA_KEY_LENGTH];
        chacha_key[..CHACHA_KEY_LENGTH].copy_from_slice(key.as_ref());

        Box::new(Tls12ChaCha20Poly1305 {
            key: chacha_key,
            iv: Iv::copy(iv),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        assert_eq!(key.as_ref().len(), CHACHA_KEY_LENGTH); // ChaCha key length must be 32 bytes.

        let mut chacha_key = [0u8; CHACHA_KEY_LENGTH];
        chacha_key[..CHACHA_KEY_LENGTH].copy_from_slice(key.as_ref());

        Box::new(Tls12ChaCha20Poly1305 {
            key: chacha_key,
            iv: Iv::copy(iv),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: CHACHA_KEY_LENGTH, // ChaCha key must be 32 bytes.
            fixed_iv_len: CHAHCA_NONCE_LENGTH,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        debug_assert_eq!(CHAHCA_NONCE_LENGTH, iv.len()); // Nonce length must be 12 for ChaCha
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv[..].try_into().unwrap()),
        })
    }
}

/// [`MessageEncrypter`] for ChaCha 1.2
/// the [`payload`] field that comes from the [`BorrowedPlainMessage`] is structured to include the message which is an arbitrary length,
/// and  the tag which is 16 bytes.
/// ex : [1, 2, 3, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                        ^  ^                                                   ^
///      Message (N bytes)                              Tag (16 bytes)
impl MessageEncrypter for Tls12ChaCha20Poly1305 {
    fn encrypt(&mut self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> {
        // Adding the size of the the message and tag to the payload vector.
        let total_len = msg.payload.len() + CHACHA_TAG_LENGTH;

        // Construct payload.
        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(msg.payload);

        // Set up needed parameters for ChaCha encrypt.
        let mut tag = [0u8; CHACHA_TAG_LENGTH];
        let nonce = Nonce::new(&self.iv, seq);
        let auth_data = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        // ChaCha Encrypt in place, only the message from the payload will be encrypted.
        match chacha20_poly1305_encrypt_in_place(
            &self.key,
            &nonce.0,
            &auth_data,
            &mut payload[..msg.payload.len()],
            &mut tag,
        ) {
            Ok(_) => {
                payload.extend_from_slice(&tag); // Add tag to the end of the payload.
                Ok(OpaqueMessage::new(
                    msg.typ,
                    msg.version,
                    payload,
                ))
            }
            Err(symcrypt_error) => {
                let custom_error_message = format!(
                    "SymCryptError: {}",
                    symcrypt_error.to_string() // Using general error to propagate the SymCrypt error back to the caller.
                );
                return Err(Error::General(custom_error_message));
            }
        }
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHA_TAG_LENGTH
    }
}

/// [`MessageDecrypter`] for ChaCha 1.2
/// the [`payload`] field that comes from the [`BorrowedOpaqueMessage`] is structured to include the message which is an arbitrary length,
/// and  the tag which is 16 bytes.
/// ex : [1, 2, 3, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                        ^  ^                                                   ^
///      Message (N bytes)                              Tag (16 bytes)
impl MessageDecrypter for Tls12ChaCha20Poly1305 {
    fn decrypt<'a>(&mut self, mut msg: BorrowedOpaqueMessage<'a>, seq: u64) -> Result<BorrowedPlainMessage<'a>, Error> {
        let payload = &msg.payload; // payload is already mutable since it is a reference to [`BorrowedPayload`] 
        let payload_len = payload.len(); // This length includes the message and the tag.
        if payload_len < CHACHA_TAG_LENGTH {
            return Err(Error::DecryptError);
        }
        let message_len = payload_len - CHACHA_TAG_LENGTH; // This length is only the message and does not include tag.

        // Set up needed parameters for ChaCha decrypt
        let nonce = Nonce::new(&self.iv, seq);
        let auth_data = make_tls12_aad(seq, msg.typ, msg.version, message_len);
        let mut tag = [0u8; CHACHA_TAG_LENGTH];
        tag.copy_from_slice(&payload[message_len..]);

        // Decrypting the payload in place, only the message from the payload will be decrypted.
        match chacha20_poly1305_decrypt_in_place(
            &self.key,
            &nonce.0,
            &auth_data,
            &mut payload[..message_len],
            &tag,
        ) {
            Ok(_) => {
                payload.truncate(message_len);
                Ok(msg.into_plain_message())
            }
            Err(symcrypt_error) => {
                let custom_error_message = format!(
                    "SymCryptError: {}",
                    symcrypt_error.to_string() // Using general error to propagate the SymCrypt error back to the caller
                );
                return Err(Error::General(custom_error_message));
            }
        }
    }
}

/// GCM 1.2
/// Tls12Gcm impls [`Tls12AeadAlgorithm`].
///
/// [`algo_type`] represents either GCM128 or GCM256 which corresponds to a 16 and 32 byte key respectively.
pub struct Tls12Gcm {
    algo_type: AesGcm,
}

/// Gcm12Decrypt impls [`MessageDecrypter`]
/// [`key`] is a [`GcmExpandedKey`] which takes in a key, and block type to return a Pin<Box<>>'d expanded key.
/// The only supported block type is AES.
/// [`iv`] is an implicit Iv that must be 4 bytes.
pub struct Gcm12Decrypt {
    key: GcmExpandedKey,
    iv: [u8; GCM_IMPLICIT_NONCE_LENGTH],
}

/// Gcm12Encrypt impls [`MessageEncrypter`]
/// [`key`] is a [`GcmExpandedKey`] which takes in a key, and block type to return a Pin<Box<>>'d expanded key.
/// The only supported block type is AES.
/// [`full_iv`] is a full_iv that includes both the implicit and the explicit iv.
pub struct Gcm12Encrypt {
    key: GcmExpandedKey,
    full_iv: [u8; GCM_FULL_NONCE_LENGTH],
}

impl Tls12AeadAlgorithm for Tls12Gcm {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        assert_eq!(iv.len(), GCM_IMPLICIT_NONCE_LENGTH);
        assert_eq!(extra.len(), 8);
        let mut full_iv = [0u8; GCM_FULL_NONCE_LENGTH];
        full_iv[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(iv);
        full_iv[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(extra);

        // Unwrapping here, in the scenarios that GcmExpandKey would fail should result in a panic, ie: Not enough memory.
        Box::new(Gcm12Encrypt {
            key: GcmExpandedKey::new(key.as_ref(), BlockCipherType::AesBlock).unwrap(),
            full_iv: full_iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        assert_eq!(iv.len(), GCM_IMPLICIT_NONCE_LENGTH);
        let mut implicit_iv = [0u8; GCM_IMPLICIT_NONCE_LENGTH];
        implicit_iv.copy_from_slice(iv);

        // Unwrapping here, in the scenarios that GcmExpandKey would fail should result in a panic, ie: Not enough memory.
        Box::new(Gcm12Decrypt {
            key: GcmExpandedKey::new(key.as_ref(), BlockCipherType::AesBlock).unwrap(),
            iv: implicit_iv,
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.algo_type.key_size(), // Can be either 16 or 32
            fixed_iv_len: GCM_IMPLICIT_NONCE_LENGTH,
            explicit_nonce_len: GCM_EXPLICIT_NONCE_LENGTH,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let mut gcm_iv = [0; GCM_FULL_NONCE_LENGTH];
        gcm_iv[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(iv);
        gcm_iv[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(explicit);

        match self.algo_type.key_size() {
            16 => Ok(ConnectionTrafficSecrets::Aes128Gcm {
                key: key,
                iv: Iv::new(gcm_iv),
            }),
            32 => Ok(ConnectionTrafficSecrets::Aes256Gcm {
                key: key,
                iv: Iv::new(gcm_iv),
            }),
        }
    }
}

/// [`MessageEncrypter`] for  Gcm 1.2
/// the [`payload`] field that comes from the [`BorrowedPlainMessage`] is structured to include the explicit iv which is 8 bytes,
/// the message which is an arbitrary length, and  the tag which is 16 bytes.
/// ex : [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                    ^  ^                        ^  ^                                                   ^
///       Explicit Iv (8 bytes)       Message (N bytes)                                  Tag (16 bytes)
impl MessageEncrypter for Gcm12Encrypt {
    fn encrypt(&mut self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> {
        let total_len = msg.payload.len() + GCM_TAG_LENGTH + GCM_EXPLICIT_NONCE_LENGTH; // Includes message, tag and explicit iv

        // Construct the payload
        let nonce = Nonce::new(&Iv::copy(&self.full_iv), seq);
        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(&nonce.0[GCM_IMPLICIT_NONCE_LENGTH..]);
        payload.extend_from_slice(msg.payload);

        let mut tag = [0u8; GCM_TAG_LENGTH];
        let auth_data = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        // Encrypting the payload in place, only the message from the payload will be encrypted, explicit iv will not be encrypted.
        // This call cannot fail.
        self.key.encrypt_in_place(
            &nonce.0,
            &auth_data,
            &mut payload[GCM_EXPLICIT_NONCE_LENGTH..msg.payload.len()],
            &mut tag,
        );
        payload.extend_from_slice(&tag);
        Ok(OpaqueMessage::new(
            msg.typ,
            msg.version,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_NONCE_LENGTH + GCM_TAG_LENGTH
    }
}

/// [`MessageDecrypter`] for  Gcm 1.2
/// the [`payload`] field that comes from the [`OpaqueMessage`] is structured to include the explicit iv which is 8 bytes,
/// the message which is an arbitrary length, and  the tag which is 16 bytes.
/// ex : [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                    ^  ^                        ^  ^                                                   ^
///       Explicit Iv (8 bytes)       Message (N bytes)                                  Tag (16 bytes)
impl MessageDecrypter for Gcm12Decrypt {
    fn decrypt<'a>(&mut self, mut msg: BorrowedOpaqueMessage<'a>, seq: u64) -> Result<BorrowedPlainMessage<'a>, Error> {
        let payload = &msg.payload; // payload is already mutable since it is a reference to [`BorrowedPayload`] 
        let payload_len = payload.len(); // This length includes the explicit iv, message and tag
        if payload_len < GCM_TAG_LENGTH + GCM_EXPLICIT_NONCE_LENGTH {
            return Err(Error::DecryptError);
        }

        // Construct nonce, the first 4 bytes of nonce will be the the implicit iv, the last 8 bytes will be the explicit iv. The explicit
        // iv is taken from the first 8 bytes of the payload. The explicit iv will not be encrypted.
        let mut nonce = [0u8; GCM_FULL_NONCE_LENGTH];
        nonce[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(&self.iv);
        nonce[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(&payload[..GCM_EXPLICIT_NONCE_LENGTH]);

        // Set up needed parameters for Gcm decrypt
        let mut tag = [0u8; GCM_TAG_LENGTH];
        tag.copy_from_slice(&payload[payload_len - GCM_TAG_LENGTH..]);
        let auth_data = make_tls12_aad(
            seq,
            msg.typ,
            msg.version,
            payload_len - GCM_TAG_LENGTH - GCM_EXPLICIT_NONCE_LENGTH,
        );

        // Decrypting the payload in place, only the message from the payload will be decrypted, explicit iv will not be decrypted.
        match self.key.decrypt_in_place(
            &nonce,
            &auth_data,
            &mut payload[GCM_EXPLICIT_NONCE_LENGTH..payload_len - GCM_TAG_LENGTH],
            &tag,
        ) {
            Ok(()) => {
                payload.truncate(payload_len - GCM_TAG_LENGTH); // Remove the tag

                // replace .dain with something else 
                // payload.drain(..GCM_EXPLICIT_NONCE_LENGTH); // Remove explicit iv
                Ok(msg.into_plain_message())
            }
            Err(symcrypt_error) => {
                let custom_error_message = format!(
                    "SymCryptError: {}",
                    symcrypt_error.to_string() // Using general error to propagate the SymCrypt error back to the caller
                );
                return Err(Error::General(custom_error_message));
            }
        }
    }
}
