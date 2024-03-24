use crate::globals::AddressReader;
use crate::globals::{EncapsulatorDecapsulator, ErrorEncapsulateDecapsulate};
use pqcrypto::kem::kyber1024::{
    decapsulate, encapsulate, keypair, Ciphertext, PublicKey, SecretKey,
};
use pqcrypto_traits::kem::Ciphertext as _;
use pqcrypto_traits::kem::PublicKey as _;
use pqcrypto_traits::kem::SharedSecret;
use pqcrypto_traits::Error;

const VERSION: &'static [u8; 2] = b"01";

/// Encapsulates and decapsulates the shared key via asymmetric key mechanism that is used for future message symmetric key encryption.
pub struct SharedKeyGeneratorWallet {
    pk: PublicKey,
    sk: SecretKey,
}

impl SharedKeyGeneratorWallet {
    #[inline]
    pub fn new() -> SharedKeyGeneratorWallet {
        let (pk, sk) = keypair();
        SharedKeyGeneratorWallet { pk, sk }
    }
}

impl EncapsulatorDecapsulator for SharedKeyGeneratorWallet {
    fn encapsulate_shared_key(
        &self,
        address: String,
    ) -> Result<(Vec<u8>, Vec<u8>), ErrorEncapsulateDecapsulate> {
        if let Ok(decoded) = bs58::decode(address).into_vec() {
            if !decoded[0..2].eq(VERSION) {
                return Err(ErrorEncapsulateDecapsulate::InvalidPublicKey);
            }
            let pub_key: Result<PublicKey, Error> = PublicKey::from_bytes(&decoded[2..]);
            match pub_key {
                Ok(p) => {
                    let (ss, ct) = encapsulate(&p);
                    return Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()));
                }
                Err(_) => return Err(ErrorEncapsulateDecapsulate::InvalidPublicKey),
            }
        }
        Err(ErrorEncapsulateDecapsulate::InvalidPublicKey)
    }
    fn decapsulate_shared_key(
        &self,
        cipher: &[u8],
    ) -> Result<Vec<u8>, ErrorEncapsulateDecapsulate> {
        let c = Ciphertext::from_bytes(&cipher);
        match c {
            Ok(ct) => {
                let ss = decapsulate(&ct, &self.sk);
                return Ok(ss.as_bytes().to_vec());
            }
            Err(_) => return Err(ErrorEncapsulateDecapsulate::InvalidCipher),
        }
    }
}

impl AddressReader for SharedKeyGeneratorWallet {
    fn address(&self) -> String {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend(VERSION.to_vec());
        buf.extend(self.pk.as_bytes());
        let enc = bs58::encode(buf);
        enc.into_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt() {
        let encrypter = SharedKeyGeneratorWallet::new();
        let decrypter: SharedKeyGeneratorWallet = SharedKeyGeneratorWallet::new();
        for _ in 0..5 {
            let cipher = encrypter.encapsulate_shared_key(decrypter.address());
            if let Ok(ct) = cipher {
            } else {
                assert_eq!(false, true);
            }
        }
    }

    #[test]
    fn decrypt() {
        let encrypter = SharedKeyGeneratorWallet::new();
        let decrypter: SharedKeyGeneratorWallet = SharedKeyGeneratorWallet::new();
        for _ in 0..5 {
            let sk_cipher = encrypter.encapsulate_shared_key(decrypter.address());
            if let Ok((sk, ct)) = sk_cipher {
                if let Ok(dec_sk) = decrypter.decapsulate_shared_key(&ct) {
                    assert_eq!(dec_sk, sk);
                } else {
                    assert!(false);
                }
            } else {
                assert!(false);
            }
        }
    }

    #[test]
    fn decrypt_bad_key() {
        let encrypter = SharedKeyGeneratorWallet::new();
        let decrypter: SharedKeyGeneratorWallet = SharedKeyGeneratorWallet::new();
        for _ in 0..5 {
            let sk_cipher = encrypter.encapsulate_shared_key(encrypter.address()); // encrypt for encrypter.
            if let Ok((sk, ct)) = sk_cipher {
                if let Ok(dec_sk) = decrypter.decapsulate_shared_key(&ct) {
                    // try to encrypt with decrypter key - should fail.
                    assert_ne!(dec_sk, sk);
                } else {
                    assert!(false);
                }

                if let Ok(dec_sk) = encrypter.decapsulate_shared_key(&ct) {
                    // try to encrypt with encrypter key - should pass.
                    assert_eq!(dec_sk, sk);
                } else {
                    assert!(false);
                }
            } else {
                assert!(false);
            }
        }
    }
}
