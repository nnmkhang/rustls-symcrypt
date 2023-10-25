//! WIP DO NOT REVIEW 


use rustls::NamedGroup;
use rustls::Error;
use rustls::crypto::{GetRandomFailed, SupportedKxGroup, CryptoProvider};

use rustls::SupportedCipherSuite;

use rust_symcrypt::ecdh::{};
use rust_symcrypt::ecurve;
use rust_symcrypt::symcrypt_random;




#[derive(Debug)]
struct SymCrypt;

impl CryptoProvider for SymCrypt {

    fn fill_random(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {

        if buf.len() == 0 { 
            return Err(GetRandomFailed)
        }
        // symcrypt_random() cannot fail. 
        let mut res = symcrypt_random(buf.len() as u64);
        buf.copy_from_slice(res.as_mut_slice());

        Ok(())
    }

    fn default_cipher_suites(&self) -> &'static [SupportedCipherSuite] {
        
    }

    fn default_kx_groups(&self) ->  &'static [&'static dyn SupportedKxGroup] {

    }

} 