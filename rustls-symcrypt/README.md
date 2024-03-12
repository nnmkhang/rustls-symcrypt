# SymCrypt Provider for Rustls

This crate provides integration for using `SymCrypt` cryptographic functionalities with the `rustls` crate, by implementing the required traits specified by `rustls`.

**Note on Platform Support:** This crate is fully supported on `Windows AMD64` and `Linux Mariner` platforms. For `Ubuntu`, support is classified as partial. While `rustls-symcrypt` has undergone some testing on `Ubuntu`,
full compatibility and performance cannot be guaranteed across all `Ubuntu` environments.

**Notes:**
- QUIC is not yet supported.
- Integration with `rustls-cng` and `rustls-platform-verifier` are in progress.

## Supported Ciphers

Supported cipher suites are listed below, ordered by preference. IE: The default configuration prioritizes `TLS13_AES_256_GCM_SHA384` over `TLS13_AES_128_GCM_SHA256`.

### TLS 1.3

```ignore
TLS13_AES_256_GCM_SHA384
TLS13_AES_128_GCM_SHA256
TLS13_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
```

**Note:** `TLS13_CHACHA20_POLY1305_SHA256` is disabled by default. Enable the `chacha` feature in your `Cargo.toml` to use this cipher suite.

### TLS 1.2

```ignore
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
```

## Supported Key Exchanges

Key exchanges are listed below, ordered by preference. IE: `SECP384R1` is preferred over `SECP256R1`.

```ignore
SECP384R1
SECP256R1
X25519 // Enabled with the `x25519` feature
```

**Note:** `X25519` is disabled by default. To enable, add `x25519` feature in your `Cargo.toml`.

## Dependencies

This crate depends on the [symcrypt](https://github.com/microsoft/rust-symcrypt) crate and requires you have the necessary `symcrypt` binaries for your architecture.
Refer to the [rust-symcrypt Quick Start Guide](https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt#quick-start-guide) to download the required binaries.

## Usage

Add `rustls-symcrypt` to your `Cargo.toml`:
**Note:** If you wish to enable `x25519` or `chacha` you may add it as a feature at this time.

```toml
[dependencies]
rustls_symcrypt = "0.1.0"
# To enable the chacha feature:
# rustls_symcrypt = {version = "0.1.0", features = ["chacha"]}
```

### Default Configuration

Use `default_symcrypt_provider()` for a `ClientConfig` that utilizes the default cipher suites and key exchange groups listed above:

```rust
use rustls::{ClientConfig, RootCertStore};
use rustls_symcrypt::default_symcrypt_provider;
use std::sync::Arc;
use webpki_roots;

fn main() {
    let mut root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
    };
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(default_symcrypt_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

    // Rest of the connection setup
}
```

### Custom Configuration

To modify or change the order of negotiated cipher suites for `ClientConfig`, use `custom_symcrypt_provider()`.

```rust
use rustls::{ClientConfig, RootCertStore};
use rustls_symcrypt::{custom_symcrypt_provider, TLS13_AES_128_GCM_SHA256, SECP256R1};
use std::sync::Arc;
use webpki_roots;

fn main() {
    let mut root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
    };

    // Set custom config of cipher suites that have been imported from rustls_symcrypt.
    let cipher_suites = vec![TLS13_AES_128_GCM_SHA256];
    let kx_group = vec![SECP256R1];

    let mut config =
        ClientConfig::builder_with_provider(Arc::new(custom_symcrypt_provider(
            Some(cipher_suites), Some(kx_group))))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth();

    // Rest of the connection setup
}
```