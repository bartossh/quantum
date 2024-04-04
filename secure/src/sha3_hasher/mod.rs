use crate::globals::Hasher;
use sha3::{Digest, Sha3_512};

/// Hash contains a specific hash wrapped to satisfy Hasher trait.
///
pub struct HashSha3_512 {
    inner: Sha3_512,
}

impl HashSha3_512 {
    pub fn new() -> Self {
        Self {
            inner: Sha3_512::new(),
        }
    }
}

impl Hasher for HashSha3_512 {
    fn hash(&mut self, slice: &[u8]) -> Vec<u8> {
        self.inner.update(slice);
        self.inner.clone().finalize().to_vec()
    }

    fn reset(&mut self) {
        self.inner.reset();
    }

    fn hash_reset(&mut self, slice: &[u8]) -> Vec<u8> {
        let h = self.hash(slice);
        self.reset();
        h
    }
}
