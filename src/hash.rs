/* Hash functions. For further documentation please refer to rust_symcrypt::hash */
use rustls::crypto::hash;
use rust_symcrypt::hash::{Sha256State, Sha384State, HashState, sha256, sha384};

pub struct Sha256;
pub struct Sha256Context(Sha256State);

impl hash::Hash for Sha256 {
    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }

    fn output_len(&self) -> usize {
        32
    }

    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(Sha256State::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&sha256(data)[..])
    }
}

impl hash::Context for Sha256Context {
    fn fork_finish(&self) -> hash::Output {
        let new_context = self.0.copy();
        hash::Output::new(&new_context.result()[..])
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(*self.0.copy()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.result()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.append(&data);
    }
}

pub struct Sha384;
struct Sha384Context(Sha384State);

impl hash::Hash for Sha384 {
    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA384
    }

    fn output_len(&self) -> usize {
        48
    }

    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha384Context(Sha384State::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&sha384(data)[..])
    }
}

impl hash::Context for Sha384Context {
    fn fork_finish(&self) -> hash::Output {
        let new_context = self.0.copy();
        hash::Output::new(&new_context.result()[..])
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Sha384Context(*self.0.copy()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.result()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.append(&data);
    }
}
