use crate::globals::{
    AddressReader, EncryptorDecryptor, EncryptorDecryptorAddressReader, ErrorSecure,
};
use rand::thread_rng;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::LineEnding,
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use sha3::Sha3_512;

const BITS: usize = 2048;
const VERSION: &'static [u8; 2] = b"01";

/// Encrypts and decrypts provided data with using asymmetric key exchange.
pub struct CipherWallet {
    pk: RsaPublicKey,
    sk: RsaPrivateKey,
}

impl CipherWallet {
    #[inline]
    pub fn new() -> Result<CipherWallet, ErrorSecure> {
        let mut rng = rand::thread_rng();

        if let Ok(private_key) = RsaPrivateKey::new(&mut rng, BITS) {
            let public_key = RsaPublicKey::from(&private_key);
            return Ok(CipherWallet {
                pk: public_key,
                sk: private_key,
            });
        }
        Err(ErrorSecure::InvalidPublicKey)
    }
}

impl AddressReader for CipherWallet {
    #[inline]
    fn address(&self) -> String {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend(VERSION.to_vec());
        if let Ok(pem) = self.pk.to_pkcs1_pem(LineEnding::LF) {
            buf.extend(pem.as_bytes());
        } else {
            return "".to_owned();
        }
        let enc = bs58::encode(buf);
        enc.into_string()
    }
}

impl EncryptorDecryptor for CipherWallet {
    fn decrypt(&self, msg: &[u8]) -> Result<Vec<u8>, ErrorSecure> {
        let padding = Oaep::new::<Sha3_512>();
        if let Ok(decrypted) = self.sk.decrypt(padding, msg) {
            return Ok(decrypted);
        }

        Err(ErrorSecure::InvalidCipher)
    }

    fn encrypt(&self, address: String, msg: &[u8]) -> Result<Vec<u8>, ErrorSecure> {
        if let Ok(decoded) = bs58::decode(address).into_vec() {
            if !decoded[0..2].eq(VERSION) {
                return Err(ErrorSecure::InvalidPublicKey);
            }
            if let Ok(pem) = String::from_utf8(decoded[2..].to_vec()) {
                if let Ok(encrypting_key) = RsaPublicKey::from_pkcs1_pem(&pem) {
                    let mut rng = thread_rng();
                    let padding = Oaep::new::<Sha3_512>();
                    if let Ok(encrypted) = encrypting_key.encrypt(&mut rng, padding, msg) {
                        return Ok(encrypted);
                    }
                    return Err(ErrorSecure::UnexpectedFailure);
                }
            }
            return Err(ErrorSecure::InvalidPublicKey);
        }
        Err(ErrorSecure::InvalidPublicKey)
    }
}

impl EncryptorDecryptorAddressReader for CipherWallet {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt() {
        let msg: &[u8] = "this is example message to encrypt".as_bytes();
        let encrypter = CipherWallet::new().unwrap();
        let decrypter = CipherWallet::new().unwrap();
        for _ in 0..5 {
            let cipher = encrypter.encrypt(decrypter.address(), &msg);
            if let Ok(_) = cipher {
            } else {
                assert_eq!(false, true);
            }
        }
    }

    #[test]
    fn decrypt() {
        let msg: &[u8] = "this is example message to encrypt".as_bytes();
        let encrypter = CipherWallet::new().unwrap();
        let decrypter = CipherWallet::new().unwrap();
        for _ in 0..5 {
            let cipher = encrypter.encrypt(decrypter.address(), &msg);
            if let Ok(ct) = cipher {
                if let Ok(dec) = decrypter.decrypt(&ct) {
                    assert_eq!(dec, msg);
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
        let msg: &[u8] = "this is example message to encrypt".as_bytes();
        let encrypter = CipherWallet::new().unwrap();
        let decrypter = CipherWallet::new().unwrap();
        for _ in 0..5 {
            let cipher = encrypter.encrypt(encrypter.address(), &msg); // encrypt for encrypter.
            if let Ok(ct) = cipher {
                if let Ok(dec) = decrypter.decrypt(&ct) {
                    // try to encrypt with decrypter key - should fail.
                    assert_ne!(dec, msg);
                } else {
                    assert!(true);
                }

                if let Ok(dec) = encrypter.decrypt(&ct) {
                    // try to encrypt with encrypter key - should pass.
                    assert_eq!(dec, msg);
                } else {
                    assert!(false);
                }
            } else {
                assert!(false);
            }
        }
    }
}
