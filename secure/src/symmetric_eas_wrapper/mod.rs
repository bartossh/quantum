use crate::globals::{ErrorSecure, SymmetricEncryptorDecryptor};
use openssl::aes::{aes_ige, AesKey};
use openssl::rand::rand_bytes;
use openssl::symm::Mode;
use std::convert::From;

const CHUNK_SIZE: usize = 16;

pub struct SymmetricSecurity {
    encrypt: AesKey,
    decrypt: AesKey,
}

impl From<&[u8; 16]> for SymmetricSecurity {
    fn from(key: &[u8; 16]) -> Self {
        Self {
            encrypt: AesKey::new_encrypt(key).unwrap(), // new_encrypt fails only if key isn't 128 bits in length, we have strict length
            decrypt: AesKey::new_decrypt(key).unwrap(), // new_decrypt fails only if key isn't 128 bits in length, we have strict length
        }
    }
}

impl From<&[u8; 24]> for SymmetricSecurity {
    fn from(key: &[u8; 24]) -> Self {
        Self {
            encrypt: AesKey::new_encrypt(key).unwrap(), // new_encrypt fails only if key isn't 192 bits in length, we have strict length
            decrypt: AesKey::new_decrypt(key).unwrap(), // new_decrypt fails only if key isn't 192 bits in length, we have strict length
        }
    }
}

impl From<&[u8; 32]> for SymmetricSecurity {
    fn from(key: &[u8; 32]) -> Self {
        Self {
            encrypt: AesKey::new_encrypt(key).unwrap(), // new_encrypt fails only if key isn't 256 bits in length, we have strict length
            decrypt: AesKey::new_decrypt(key).unwrap(), // new_decrypt fails only if key isn't 256 bits in length, we have strict length
        }
    }
}

impl SymmetricEncryptorDecryptor for SymmetricSecurity {
    fn encrypt(&self, message: &[u8]) -> Result<(Vec<u8>, [u8; 32], usize), ErrorSecure> {
        let rest = message.len() % CHUNK_SIZE;
        let message = match rest {
            0 => message.to_vec(),
            _ => {
                let mut extended: Vec<u8> = Vec::with_capacity(message.len() + CHUNK_SIZE - rest);
                extended.extend(message);
                extended.extend(vec![0; CHUNK_SIZE - rest]);

                extended
            }
        };

        let mut nonce = [0; 32];
        let Ok(_) = rand_bytes(&mut nonce) else {
            return Err(ErrorSecure::UnexpectedFailure);
        };
        let mut cipher: Vec<u8> = vec![0; message.len()];
        aes_ige(
            &message,
            &mut cipher,
            &self.encrypt,
            &mut nonce.clone(),
            Mode::Encrypt,
        );

        Ok((cipher, nonce, if rest == 0 { 0 } else { CHUNK_SIZE - rest }))
    }

    fn decrypt(&self, cipher: &[u8], nonce: &[u8; 32], padding: usize) -> Vec<u8> {
        let mut message: Vec<u8> = vec![0; cipher.len()];
        aes_ige(
            &cipher,
            &mut message,
            &self.decrypt,
            &mut nonce.to_vec(),
            Mode::Decrypt,
        );
        message.truncate(cipher.len() - padding);

        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng, RngCore};
    use std::convert::From;

    #[test]
    fn it_should_encrypt_data_of_any_size_successfully() {
        let mut rng = rand::thread_rng();
        for extended in 0..=16 {
            let mut message: Vec<u8> = vec![0; 16 * 100 + extended];
            rng.fill_bytes(&mut message);
            let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
            let security = SymmetricSecurity::from(key);
            let Ok((cipher, nonce, padding)) = security.encrypt(&message) else {
                assert!(false);
                return;
            };
            assert_eq!(
                cipher.len(),
                if padding == 0 {
                    message.len()
                } else {
                    message.len() - extended + CHUNK_SIZE
                }
            );
            assert_eq!(nonce.len(), 32);
            assert_eq!(
                padding,
                if extended == 0 {
                    0
                } else {
                    CHUNK_SIZE - extended
                }
            );
        }
    }

    #[test]
    fn it_should_encrypt_decrypt_data_of_any_size_successfully() {
        let mut rng = rand::thread_rng();
        for extended in 0..=16 {
            let mut message: Vec<u8> = vec![0; 16 * 100 + extended];
            rng.fill_bytes(&mut message);
            let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
            let security = SymmetricSecurity::from(key);
            let Ok((cipher, nonce, padding)) = security.encrypt(&message) else {
                assert!(false);
                return;
            };
            assert_eq!(
                cipher.len(),
                if padding == 0 {
                    message.len()
                } else {
                    message.len() - extended + CHUNK_SIZE
                }
            );
            assert_eq!(nonce.len(), 32);
            assert_eq!(
                padding,
                if extended == 0 {
                    0
                } else {
                    CHUNK_SIZE - extended
                }
            );

            let plane = security.decrypt(&cipher, &nonce, padding);

            assert_eq!(message, plane);
        }
    }

    #[test]
    fn it_should_encrypt_and_not_decrypt_altered_data() {
        let mut rng = rand::thread_rng();
        for extended in 0..=16 {
            let mut message: Vec<u8> = vec![0; 16 * 100 + extended];
            rng.fill_bytes(&mut message);
            let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
            let security = SymmetricSecurity::from(key);
            let Ok((mut cipher, nonce, padding)) = security.encrypt(&message) else {
                assert!(false);
                return;
            };
            assert_eq!(
                cipher.len(),
                if padding == 0 {
                    message.len()
                } else {
                    message.len() - extended + CHUNK_SIZE
                }
            );
            assert_eq!(nonce.len(), 32);
            assert_eq!(
                padding,
                if extended == 0 {
                    0
                } else {
                    CHUNK_SIZE - extended
                }
            );

            let idx = thread_rng().gen_range(0..cipher.len());
            cipher[idx] = if cipher[idx] == 255 {
                0
            } else {
                cipher[idx] + 1
            };

            let plane = security.decrypt(&cipher, &nonce, padding);

            assert_ne!(message, plane);
        }
    }
}
