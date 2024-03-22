use crate::traits::{EncapsulatorDecapsulator, ErrorEncryptDecrypt};
use pqcrypto::kem::kyber1024::{
    decapsulate, encapsulate, keypair, Ciphertext, PublicKey, SecretKey,
};
use pqcrypto_traits::kem::Ciphertext as _;
use pqcrypto_traits::kem::PublicKey as _;
use pqcrypto_traits::kem::SharedSecret;
use pqcrypto_traits::Error;

/// Encapsulates and decapsulates the shared key via asymmetric key mechanism that is used for future message symmetric key encryption.
pub struct SharedKeyGeneratorWallet {
    pk: PublicKey,
    sk: SecretKey,
}

impl SharedKeyGeneratorWallet {
    pub fn new() -> SharedKeyGeneratorWallet {
        let (pk, sk) = keypair();
        SharedKeyGeneratorWallet { pk, sk }
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.pk.as_bytes().to_vec()
    }
}

impl EncapsulatorDecapsulator for SharedKeyGeneratorWallet {
    fn encapsulate_shared_key(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ErrorEncryptDecrypt> {
        let pub_key: Result<PublicKey, Error> = PublicKey::from_bytes(pk);
        match pub_key {
            Ok(p) => {
                let (ss, ct) = encapsulate(&p);
                return Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()));
            }
            Err(_) => return Err(ErrorEncryptDecrypt::InvalidPublicKey),
        }
    }
    fn decapsulate_shared_key(&self, cipher: &[u8]) -> Result<Vec<u8>, ErrorEncryptDecrypt> {
        let c = Ciphertext::from_bytes(&cipher);
        match c {
            Ok(ct) => {
                let ss = decapsulate(&ct, &self.sk);
                return Ok(ss.as_bytes().to_vec());
            }
            Err(_) => return Err(ErrorEncryptDecrypt::InvalidCipher),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt() {
        let encrypter = SharedKeyGeneratorWallet::new();
        let decrypter: SharedKeyGeneratorWallet = SharedKeyGeneratorWallet::new();
        for i in 0..5 {
            let cipher = encrypter.encapsulate_shared_key(&decrypter.public_key());
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
        for i in 0..5 {
            let sk_cipher = encrypter.encapsulate_shared_key(&decrypter.public_key());
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
        for i in 0..5 {
            let sk_cipher = encrypter.encapsulate_shared_key(&encrypter.public_key()); // encrypt for encrypter.
            if let Ok((sk, ct)) = sk_cipher {
                if let Ok(dec_sk) = decrypter.decapsulate_shared_key(&ct) {
                    // try to encrypt with decrypter key - should fail.
                    assert_ne!(dec_sk, sk);
                } else {
                    assert!(true);
                }

                if let Ok(dec_sk) = encrypter.decapsulate_shared_key(&ct) {
                    // try to encrypt with encrypter key - should pass.
                    assert_eq!(dec_sk, sk);
                } else {
                    assert!(true);
                }
            } else {
                assert!(false);
            }
        }
    }
}
