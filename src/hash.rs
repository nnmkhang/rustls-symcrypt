use rustls::sign;
use rustls::crypto;
use rust_symcrypt::hash::sha256;
pub struct SHA256;


impl hash::Hash for SHA256 {
    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }

    fn output_len(&self) -> usize {
        32
    }

    fn start(&self) -> Box<dyn hash::Context> { // Context is the name for "state" 

    }

    fn compute(&self, data: &[u8]) -> hash::Output {
        let result = sha256(data);
        hash::Output::new(&sha256(data)[..])
    }

}