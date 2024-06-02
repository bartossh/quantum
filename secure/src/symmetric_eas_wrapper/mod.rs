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
    fn encrypt(&self, message: &[u8]) -> Result<(Vec<u8>, Vec<u8>, usize), ErrorSecure> {
        let rest = message.len() % CHUNK_SIZE;
        let message = match rest {
            0 => message.to_vec(),
            _ => {
                let mut extended: Vec<u8> = Vec::with_capacity(message.len() + CHUNK_SIZE - rest);
                extended.extend_from_slice(message);
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
            &mut nonce,
            Mode::Encrypt,
        );

        return Ok((
            cipher,
            nonce.to_vec(),
            if rest == 0 { 0 } else { CHUNK_SIZE - rest },
        ));
    }

    fn decrypt(&self, cipher: &[u8], nonce: &[u8; 32]) -> Vec<u8> {
        let mut message: Vec<u8> = vec![0; cipher.len()];
        aes_ige(
            &cipher,
            &mut message,
            &self.decrypt,
            &mut nonce.to_vec(),
            Mode::Decrypt,
        );

        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::From;

    #[test]
    fn it_should_encrypt_data_of_chunk_size_multiple() {
        let message: Vec<u8> = vec![123; 16 * 100];
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let security = SymmetricSecurity::from(key);
        let Ok((cipher, nonce, usize)) = security.encrypt(&message) else {
            assert!(false);
            return;
        };
        assert_eq!(cipher.len(), message.len());
        assert_eq!(nonce.len(), 32);
        assert_eq!(usize, 0);
    }
}
