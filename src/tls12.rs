//! GCM and ChaCha functions for TLS 1.3. For further documentation please refer to rust_symcrypt::gcm and symcrypt::chacha

use rustls::crypto::cipher::{Tls12AeadAlgorithm, MessageEncrypter, MessageDecrypter, Nonce, OpaqueMessage, PlainMessage, make_tls12_aad, KeyBlockShape, Iv};
use rust_symcrypt::gcm::GcmExpandedKey;
use rust_symcrypt::chacha::{chacha20_poly1305_decrypt_in_place, chacha20_poly1305_encrypt_in_place};
use rust_symcrypt::block_ciphers::BlockCipherType;

const CHACHA_TAG_LENGTH: usize = 16;
const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const GCM_TAG_LENGTH: usize = 16;

/// ChaCha for TLS 1.2
/// 
/// [`Tls12ChaCha`] impls [`Tls12AeadAlgorithm`].
pub struct Tls12ChaCha;

/// [`TLs12ChaCha20Poly1305`] impls [`MessageEncrypter`] and [`MessageDecrypter`]
/// [`key`] is a ChaCha key and must be 32 bytes long.
/// [`iv`] is an initialization vector that is needed to create the unique nonce.
pub struct Tls12ChaCha20Poly1305 {key: [u8; 32], iv: rustls::crypto::cipher::Iv}

impl Tls12AeadAlgorithm for Tls12ChaCha { 
    fn encrypter(&self, key: rustls::crypto::cipher::AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        assert_eq!(key.as_ref().len(), 32); // ChaCha key length must be 32 bytes.

        let mut chacha_key = [0u8; 32]; 
        chacha_key[..32].copy_from_slice(key.as_ref());

        Box::new(Tls12ChaCha20Poly1305 {key: chacha_key, iv: Iv::copy(iv)}) 
    }

    fn decrypter(&self, key: rustls::crypto::cipher::AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        assert_eq!(key.as_ref().len(), 32); // ChaCha key length must be 32 bytes.

        let mut chacha_key = [0u8; 32];
        chacha_key[..32].copy_from_slice(key.as_ref());

        Box::new(Tls12ChaCha20Poly1305 {key: chacha_key, iv: Iv::copy(iv)})   
    }

    fn key_block_shape(&self) -> rustls::crypto::cipher::KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32, // ChaCha key must be 32 bytes.
            fixed_iv_len: 4,
            explicit_nonce_len: 8,
        }
    }
}

/// [`MessageEncrypter`] for ChaCha 1.2
/// the [`payload`] field that comes from the [`BorrowedPlainMessage`] is structured to include the message which is an arbitrary length, 
/// and  the tag which is 16 bytes. 
/// ex : [1, 2, 3, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                        ^  ^                                                   ^
///      Message (N bytes)                              Tag (16 bytes)
impl MessageEncrypter for Tls12ChaCha20Poly1305 {
    fn encrypt(&self, msg: rustls::crypto::cipher::BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, rustls::Error> {
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
        match chacha20_poly1305_encrypt_in_place(&self.key, &nonce.0, &auth_data, &mut payload[..msg.payload.len()], &mut tag) {
            Ok(_) => {
                payload.extend_from_slice(&tag); // Add tag to the end of the payload.
                Ok(OpaqueMessage::new(rustls::ContentType::ApplicationData, rustls::ProtocolVersion::TLSv1_2, payload))
            }
            Err(symcrypt_error) => {
                let custom_error_message = format!(
                    "SymCryptError: {}",
                    symcrypt_error.to_string() // Using general error to propagate the SymCrypt error back to the caller.
                );
                return Err(rustls::Error::General(custom_error_message));
            }
        }
    }
}

/// [`MessageDecrypter`] for ChaCha 1.2
/// the [`payload`] field that comes from the [`OpaqueMessage`] is structured to include the message which is an arbitrary length, 
/// and  the tag which is 16 bytes. 
/// ex : [1, 2, 3, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                        ^  ^                                                   ^
///      Message (N bytes)                              Tag (16 bytes)
impl MessageDecrypter for Tls12ChaCha20Poly1305{
    fn decrypt(&self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, rustls::Error> {
        let payload_len = msg.payload().len(); // This length includes the message and the tag.
        let message_len = payload_len - CHACHA_TAG_LENGTH;  // This length is only the message and does not include tag.

        if payload_len < CHACHA_TAG_LENGTH {
            return Err(rustls::Error::DecryptError);
        }

        // Set up needed parameters for ChaCha decrypt
        let nonce = Nonce::new(&self.iv, seq);
        let auth_data = make_tls12_aad(seq, msg.typ, msg.version, message_len);
        let mut payload = msg.payload_mut();
        let mut tag = [0u8; CHACHA_TAG_LENGTH];
        tag.copy_from_slice(&payload[message_len..]);        

        // Decrypting the payload in place, only the message from the payload will be decrypted.
        match chacha20_poly1305_decrypt_in_place(&self.key, &nonce.0, &auth_data, &mut payload[..message_len], &tag) {
            Ok(_) => {
                payload.truncate(message_len);
                Ok(msg.into_plain_message())
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

/// GCM 1.2
/// Tls12Gcm impls [`Tls12AeadAlgorithm`].
pub struct Tls12Gcm;

/// Gcm12Decrypt impls [`MessageDecrypter`]
/// [`key`] is a [`GcmExpandedKey`] which takes in a key, and block type to return a Pin<Box<>>'d expanded key.
/// The only supported block type is AES.
/// [`iv`] is an implicit Iv that must be 4 bytes.
pub struct Gcm12Decrypt {
    key: GcmExpandedKey, 
    iv: [u8; 4]
}

/// Gcm12Encrypt impls [`MessageEncrypter`]
/// [`key`] is a [`GcmExpandedKey`] which takes in a key, and block type to return a Pin<Box<>>'d expanded key.
/// The only supported block type is AES.
/// [`full_iv`] is a full_iv that includes both the implicit and the explicit iv.
pub struct Gcm12Encrypt {
    key: GcmExpandedKey,
    full_iv: [u8; 12]
}

impl Tls12AeadAlgorithm for Tls12Gcm { 
    fn encrypter(&self, key: rustls::crypto::cipher::AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        assert_eq!(iv.len(), 4);
        assert_eq!(extra.len(), 8);
        let mut full_iv = [0u8; 12];
        full_iv[..4].copy_from_slice(iv);
        full_iv[4..].copy_from_slice(extra);

        // Unwrapping here, in the scenarios that GcmExpandKey would fail should result in a panic, ie: Not enough memory.
        Box::new(Gcm12Encrypt{key: GcmExpandedKey::new(key.as_ref(), BlockCipherType::AesBlock).unwrap(), full_iv: full_iv}) 
    }

    fn decrypter(&self, key: rustls::crypto::cipher::AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> { 
        assert_eq!(iv.len(), 4); 
        let mut implicit_iv = [0u8; 4];
        implicit_iv.copy_from_slice(iv);

        // Unwrapping here, in the scenarios that GcmExpandKey would fail should result in a panic, ie: Not enough memory.
        Box::new(Gcm12Decrypt{key: GcmExpandedKey::new(key.as_ref(), BlockCipherType::AesBlock).unwrap(), iv: implicit_iv})
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32, // Key length is 32
            fixed_iv_len: 4,
            explicit_nonce_len: GCM_EXPLICIT_NONCE_LEN,
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
    fn encrypt(&self, msg: rustls::crypto::cipher::BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, rustls::Error> {
        let total_len = msg.payload.len() + GCM_TAG_LENGTH + GCM_EXPLICIT_NONCE_LEN; // Includes message, tag and explcit iv

        // Construct the payload
        let nonce = Nonce::new(&Iv::copy(&self.full_iv), seq);
        let mut payload = Vec::with_capacity(total_len); 
        payload.extend_from_slice(&nonce.0[4..]);
        payload.extend_from_slice(msg.payload);

        let mut tag = [0u8; GCM_TAG_LENGTH];
        let auth_data = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        // Encrypting the payload in place, only the message from the payload will be encrypted, explicit iv will not be encrypted. 
        // This call cannot fail.
        self.key.encrypt_in_place(&nonce.0, &auth_data, &mut payload[GCM_EXPLICIT_NONCE_LEN..msg.payload.len()], &mut tag);
        payload.extend_from_slice(&tag); 
        Ok(OpaqueMessage::new(rustls::ContentType::ApplicationData, rustls::ProtocolVersion::TLSv1_2, payload)) 
    }
}

/// [`MessageDecrypter`] for  Gcm 1.2
/// the [`payload`] field that comes from the [`OpaqueMessage`] is structured to include the explicit iv which is 8 bytes,
/// the message which is an arbitrary length, and  the tag which is 16 bytes. 
/// ex : [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                    ^  ^                        ^  ^                                                   ^
///       Explicit Iv (8 bytes)       Message (N bytes)                                  Tag (16 bytes)
impl MessageDecrypter for Gcm12Decrypt{
    fn decrypt(&self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, rustls::Error> {
        let payload_len = msg.payload().len(); // This length includes the explicit iv, message and tag 
        if payload_len < GCM_TAG_LENGTH {
            return Err(rustls::Error::DecryptError);
        }

        // Construct nonce, the first 4 bytes of nonce will be the the implicit iv, the last 8 bytes will be the explicit iv. The explicit
        // iv is taken from the first 8 bytes of the payload. The explicit iv will not be encrypted. 
        let payload = msg.payload();
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.iv);
        nonce[4..].copy_from_slice(&payload[..GCM_EXPLICIT_NONCE_LEN]);

        // Set up needed parameters for Gcm decrypt
        let mut tag = [0u8; GCM_TAG_LENGTH];
        tag.copy_from_slice(&payload[payload_len-GCM_TAG_LENGTH..]);
        let auth_data = make_tls12_aad(seq, msg.typ, msg.version, payload_len-GCM_TAG_LENGTH-GCM_EXPLICIT_NONCE_LEN);

        let mut payload = msg.payload_mut(); // Re-define payload with mutable reference

        // Decrypting the payload in place, only the message from the payload will be decrypted, explicit iv will not be decrypted.
        match self.key.decrypt_in_place(&nonce, &auth_data, &mut payload[GCM_EXPLICIT_NONCE_LEN..payload_len-GCM_TAG_LENGTH], &tag) {
            Ok(()) => {
                // remove first 8 bytes, can shift, do this fist
                payload.truncate(payload_len-GCM_TAG_LENGTH); // Remove the tag
                payload.drain(..GCM_EXPLICIT_NONCE_LEN); // Remove explicit iv
                Ok(msg.into_plain_message())
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
