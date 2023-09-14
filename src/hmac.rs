use rustls::crypto::hmac;
use rust_symcrypt::hmac::{HmacSha256State, HmacSha384State, Hmac};

pub struct HmacSha256;
pub struct HmacSha256Key(HmacSha256State);
pub struct HmacSha384;
pub struct HmacSha384Key(HmacSha384State);


impl hmac::Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn hmac::Key> {
        Box::new(HmacSha256Key(HmacSha256State::new(key)))
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

impl hmac::Hmac for HmacSha384 {
    fn with_key(&self, key: &[u8]) -> Box<dyn hmac::Key> {
        Box::new(HmacSha384Key(HmacSha384State::new(key)))
    }

    fn hash_output_len(&self) -> usize {
        48
    }
}

impl hmac::Key for HmacSha256Key {
    fn sign(&self, data: &[&[u8]]) -> hmac::Tag {
        self.sign_concat(&[], data, &[])
    }

    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> hmac::Tag {
        let mut new_state = *self.0.copy();
        new_state.append(first);
        for d in middle {
            new_state.append(d);
        }
        new_state.append(last);

        let result = new_state.result();
        hmac::Tag::new(&result)
    }

    fn tag_len(&self) -> usize {
        32
    }
}

impl hmac::Key for HmacSha384Key {
    fn sign(&self, data: &[&[u8]]) -> hmac::Tag {
        self.sign_concat(&[], data, &[])
    }

    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> hmac::Tag {
        let mut new_state = *self.0.copy();
        new_state.append(first);
        for d in middle {
            new_state.append(d);
        }
        new_state.append(last);

        let result = new_state.result();
        hmac::Tag::new(&result)
    }

    fn tag_len(&self) -> usize {
        48
    }
}
