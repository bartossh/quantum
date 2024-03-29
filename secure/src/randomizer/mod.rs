use digest::Digest;
use rand::Rng;
use sha3::Sha3_256;

pub fn random_hash() -> Vec<u8> {
    let mut arr = [0u8; 256];
    rand::thread_rng().fill(&mut arr[..]);

    let mut hasher = Sha3_256::new();
    hasher.update(&arr);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_random_hash() {
        let rounds: usize = 100;
        let mut hs: HashSet<Vec<u8>> = HashSet::new();
        for _ in 0..rounds {
            let h = random_hash();
            assert_eq!(h.len(), 32);
            hs.insert(h);
        }
        assert_eq!(hs.len(), rounds);
    }
}
