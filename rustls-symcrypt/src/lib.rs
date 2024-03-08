// # SymCrypt Provider for Rustls
//!
//! This crate provides a way to use `SymCrypt` cryptography with the `rustls` crate. This is done via implementing the required traits specified by the `rustls` crate.
//!
//! **Note: Only windows AMD64 and Linux mariner are fully supported, with partial support for Ubuntu**
//!
//!  ## Supported Ciphers:
//!
//! The supported Ciphers are listed below. This is a ranking based on highest preference; IE: `TLS13_AES_256_GCM_SHA384` has higher preference than `TLS13_AES_128_GCM_SHA256` for the default configuration
//!
//! TLS 1.3
//! ```
//! TLS13_AES_256_GCM_SHA384
//! TLS13_AES_128_GCM_SHA256
//! TLS13_CHACHA20_POLY1305_SHA256 // disabled by default, enable the `chacha` feature to enable
//! ```
//! **Note: `TLS13_CHACHA20_POLY1305_SHA256` will be disabled by default for both TLS 1.3 and TLS 1.2. To enable use the `chacha` feature to enable this `CipherSuite`
//! TLS 1.2 
//!
//! ```
//! TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
//! TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
//! 
//! #[cfg(feature = "chacha")]
//! TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
//! TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
//!
//! TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
//! #[cfg(feature = "chacha")]
//! TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
//! ```
//!
//! **Note: QUIC is not yet supported**
//!
//! **Note: Intergration with rustls-cng and rustls-platform verifier are in the works**
//!
//! ## Supported Key Exchanges
//! The supported Key Exchanges are listed below. This is a ranking based on highest preference. IE: `SECP384R1` has higher priority than `SECP256R1` for the default configuration. 
//! ```
//! SECP384R1
//! SECP256R1
//! #[cfg(feature = "x25519")]
//! X25519
//! ```
//! 
//! **Note: `X25519` will be disabled by default. To enable, use the `x25519` feature to enable this `KeyExchange`
//!
//! ## Dependencies 
//!
//! This crate has dependency on the [symcrypt](https://github.com/microsoft/rust-symcrypt) crate. In order for this crate to work, you must have the required `symcrypt` binaries on your machine. Please download the required `symcrypt` binaries for your desired architecture from the [symcrypt artifacts](asdf) page. And then follow the instructions on [symcrypt quick start guide](asdf). For more information, or a custom configuration please see the info on [building symcrypt](asdf)
//!
//!
//! ## Usage 
//!
//!
//!
//! add `rustls-symcrypt` to your `Cargo.toml` file.
//! 
//! ```rust
//! [dependencies]
//! rustls_symcrypt = "0.1.0";
//! ```
//! ### Default configuration 
//! To get a `ClientConfig` that uses the `SymCrypt`'s underlying crypto you can import and use the `default_symcrypt_provider()` with `rustls::ClientConfig::builder_with_provider()`.
//!
//! **Note: There are some ciphers that will not be negotiated by default, to see the list of default ciphers please see Supported Ciphers above.**
//!
//!  ```rust
//! use rustls::{ClientConfig, RootCertStore};
//! use rustls_symcrypt::default_symcrypt_provider;
//! use std::sync::Arc;
//! use webpki_roots;
//!
//! fn main() {
//! 	
//!     let mut root_store = RootCertStore {
//!         roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
//!     };
//! 
//! 	// Config set up
//! 	
//!     let mut config =
//! 		ClientConfig::builder_with_provider(Arc::new(default_symcrypt_provider()))
//! 	.with_safe_default_protocol_versions()
//! 	.unwrap()
//! 	.with_root_certificates(root_store)
//! 	.with_no_client_auth();
//! 	
//! 	// Rest of the connection setup
//! }
//! ```
//!
//! ### Custom configuration
//!
//! To modify, or change the order of the negotiated cipher suites for `ClientConfig` you can use `custom_symcrypt_provider()`.  
//!
//!
//!  ```rust
//! use rustls::{ClientConfig, RootCertStore};
//! use rustls_symcrypt::{custom_symcrypt_provider, TLS13_AES_128_GCM_SHA256, SECP256R1};
//! use std::sync::Arc;
//! use webpki_roots;
//!
//! fn main() {
//! 	
//!     let mut root_store = RootCertStore {
//!         roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
//!     };
//!
//! 	// Config set up	
//! 	
//! 	let  cipher_suites = vec![TLS13_AES_128_GCM_SHA256];
//! 	let  kx_group = vec![SECP256R1];
//!
//! 	let mut config =
//! 		ClientConfig::builder_with_provider(Arc::new(custom_symcrypt_provider(
//! 		Some(cipher_suites),Some(kx_group)).unwrap()))
//! 			.with_safe_default_protocol_versions()
//! 			.unwrap()
//! 			.with_root_certificates(root_store)
//! 			.with_no_client_auth();
//! 	
//! 	// Rest of the connection setup
//! }
//! ```


use rustls::crypto::{
    CryptoProvider, GetRandomFailed, SecureRandom, SupportedKxGroup,
    WebPkiSupportedAlgorithms,
};
use rustls::{SignatureScheme, SupportedCipherSuite};
use symcrypt::symcrypt_random;
use webpki::ring as webpki_algs;

mod ecdh;
mod hash;
mod hmac;
mod tls12;
mod tls13;
mod cipher_suites;
mod signer;

// TODO:
// Add comments to the code / clean up code ( unused imports, etc. )
// test on linux 

/// Exporting supported cipher suites for TLS 1.2
pub use cipher_suites::{
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};

/// Exporting supported cipher suites for TLS 1.3
pub use cipher_suites::{
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
};

pub use ecdh::{SECP256R1, SECP384R1, X25519};

/// `symcrypt_provider` returns a `CryptoProvider` using the default `SymCrypt` configuration and cipher suites.
/// To see the default cipher suites, please take a look at [`DEFAULT_CIPHER_SUITES`].
pub fn default_symcrypt_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
        kx_groups: ecdh::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &SymCrypt,
        key_provider: &signer::Ring,
    }
}

// pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[X25519, SECP256R1, SECP384R1];

/// `symcrypt_provider_with_cipher_suites` takes in an optional `Vec<>` of `[SupportedCipherSuites]` and an optional `Vec<>` of `[SupportedKxGroup]`.
/// The supplied arguments will be used when when negotiating the TLS cipher suite; and should be placed in preference order, where the first element
/// has highest priority. if None is provided for either case, the default will be used instead.  
/// should block this behind a dangerous?
/// should fail if no kx group or no cipher suite is passed
pub fn custom_symcrypt_provider(
    provided_cipher_suites: Option<Vec<SupportedCipherSuite>>,
    provided_kx_group: Option<Vec<&'static dyn SupportedKxGroup>>,
) -> Result<CryptoProvider, &'static str> {
    // check for valid arguments is not needed since the input is type casted to `SupportedCipherSuites`. The `new()` of `SupportedCipherSuites` is not
    // exported so the user cannot input an invalid array.
    // Should we also check if the array is empty?
    // if the user does the same cipher suite over and over again it would still be fine because
    let cipher_suites = match provided_cipher_suites {
        Some(suites) if !suites.is_empty() => suites,
        _ => DEFAULT_CIPHER_SUITES.to_vec(),
    };
    
    let kx_group = match provided_kx_group {
        Some(val) if !val.is_empty() => val,
        _ => ecdh::ALL_KX_GROUPS.to_vec(),
    };
    
    Ok(CryptoProvider {
        cipher_suites,
        kx_groups: kx_group,
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &SymCrypt,
        key_provider: &signer::Ring,
    })
}

/// List of SymCrypt supported cipher suites in a preference order.
/// The first element has highest priority when negotiating cipher suites.
pub static DEFAULT_CIPHER_SUITES: &[SupportedCipherSuite] = ALL_CIPHER_SUITES;

static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // TLS1.3 suites
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
    #[cfg(feature = "chacha")]
    TLS13_CHACHA20_POLY1305_SHA256,

    // TLS1.2 suites
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "chacha")]
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "chacha")]
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::ECDSA_P256_SHA384,
        webpki_algs::ECDSA_P384_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
        webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512,
        webpki_algs::RSA_PKCS1_3072_8192_SHA384,
    ],
    mapping: &[
        // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                webpki_algs::ECDSA_P384_SHA384,
                webpki_algs::ECDSA_P256_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                webpki_algs::ECDSA_P256_SHA256,
                webpki_algs::ECDSA_P384_SHA256,
            ],
        ),
        (SignatureScheme::ED25519, &[webpki_algs::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA256],
        ),
    ],
};

#[derive(Debug)]
struct SymCrypt;

impl SecureRandom for SymCrypt {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        symcrypt_random(buf);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_secure_random() {
        let random = SymCrypt;
        let mut buff_1 = [0u8; 10];
        let mut buff_2 = [0u8; 10];

        let _ = random.fill(&mut buff_1);
        let _ = random.fill(&mut buff_2);

        assert_ne!(buff_1, buff_2);
    }
}
