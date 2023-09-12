use rustls::crypto::hash; // import the hash module from rustls
use rust_symcrypt::hash::{Sha256State, HashState, Sha256, Sha384, HashAlgorithms};
use rust_symcrypt::hash::Hash as SymCryptHash;
use rust_symcrypt::hash::Sha256 as SymCryptSha256;



// pub trait Hash {
//     type Result;
//     type State: HashState<Result = Self::Result>;

//     fn get_output_length(&self) -> usize;
//     fn new_state(&self) -> Self::State;
//     fn get_algorithm(&self) -> HashAlgorithms;
//     fn hash(self, data: &[u8]) -> Self::Result;
// }

// pub trait HashState {
//     type Result;

//     fn append(&mut self, data: &[u8]);
//     fn result(self) -> Self::Result;
//     fn copy(&self) -> Self;
// }











// pub(crate) static SHA256: Hash = Hash(&ring::digest::SHA256, HashAlgorithm::SHA256);
// pub(crate) static SHA384: Hash = Hash(&ring::digest::SHA384, HashAlgorithm::SHA384);

// pub(crate) struct Hash(&'static ring::digest::Algorithm, HashAlgorithm);

// impl crypto::hash::Hash for Hash {
//     fn start(&self) -> Box<dyn crypto::hash::Context> {
//         Box::new(Context(ring::digest::Context::new(self.0)))
//     }

//     fn hash(&self, bytes: &[u8]) -> crypto::hash::Output {
//         let mut ctx = ring::digest::Context::new(self.0);
//         ctx.update(bytes);
//         ctx.finish().into()
//     }

//     fn output_len(&self) -> usize {
//         self.0.output_len
//     }

//     fn algorithm(&self) -> HashAlgorithm {
//         self.1
//     }
// }

// pub(crate) static SHA256: Hash = Hash(&ring::digest::SHA256, HashAlgorithm::SHA256);
// pub(crate) static SHA384: Hash = Hash(&ring::digest::SHA384, HashAlgorithm::SHA384);
// pub(crate) struct Hash(&'static ring::digest::Algorithm, HashAlgorithm);


// impl<T> hash::Hash for T where T: HashState { ... }

pub struct SHA256(SymCryptSha256);
pub struct Sha256Context(Sha256State);

pub struct SymCryptContext(dyn HashState<Result = Box<[u8]>>);
pub(crate) struct Hash(dyn SymCryptHash<Result = Box<[u8]>, State = dyn HashState<Result = Box<[u8]>>>);
//pub(crate) struct HashBlah(SymCryptHash);


impl hash::Hash for Hash {
    fn algorithm(&self) -> hash::HashAlgorithm {
        self.get_algorithm()
    }

    fn output_len(&self) -> usize {
        self.get_output_length()
    }

    fn start(&self) -> Box<dyn hash::Context> { 
        Box::new(Sha256Context(self.start()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(self.hash(data)[..])
    }
}

impl hash::Context for SymCryptContext {
    fn fork_finish(&self) -> hash::Output {
        let new_context = self.0.copy();
        hash::Output::new(&new_context.result()[..])
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(self.0.copy()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.result()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.append(&data);
    }
}


// fn map_algorithm(symcrypt_algo: rust_symcrypt::hash::HashAlgorithms) -> hash::HashAlgorithm {
//     match symcrypt_algo {
//         rust_symcrypt::hash::SHA256 => hash::HashAlgorithm::SHA256,
//         rust_symcrypt::hash::SHA384 => hash::HashAlgorithm::SHA384,
//     }
// }

// Bellow was how I was doing this before, I would have to impl hash::Hash and hash::Context for both Sha256
// and Sha384, I wanted to make a trait on the rust-symcrypt side so I would only have to do one impl


// pub struct SHA384; // Define the SHA384 struct
// struct SHA384Context(Sha384State); // creating a "SHA256Context" which is a wrapper over Sha256State

// impl hash::Hash for SHA384 {
//     fn algorithm(&self) -> hash::HashAlgorithm {
//         hash::HashAlgorithm::SHA384
//     }

//     fn output_len(&self) -> usize {
//         48 // Adjust the output length for SHA-384
//     }

//     fn start(&self) -> Box<dyn hash::Context> {
//         Box::new(SHA384Context(Sha384State::new())) // Create a context for SHA-384
//     }

//     fn hash(&self, data: &[u8]) -> hash::Output {
//         hash::Output::new(&sha384(data)[..])
//     }
// }

// impl hash::Context for SHA384Context {
//     fn fork_finish(&self) -> hash::Output {
//         let new_context = self.0.copy();
//         hash::Output::new(&new_context.result()[..])
//     }

//     fn fork(&self) -> Box<dyn hash::Context> {
//         Box::new(SHA384Context(self.0.copy()))
//     }

//     fn finish(self: Box<Self>) -> hash::Output {
//         hash::Output::new(&self.0.result()[..])
//     }

//     fn update(&mut self, data: &[u8]) {
//         self.0.append(&data);
//     }
// }
