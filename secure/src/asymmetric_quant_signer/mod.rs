use crate::globals::{AddressReader, ErrorSecure, Signer, SignerVerifierAddressReader, Verifier};
use pqcrypto::sign::sphincsshake256fsimple::{
    detached_sign, keypair, verify_detached_signature, DetachedSignature, PublicKey, SecretKey,
};
use pqcrypto_traits::sign::{DetachedSignature as DetachedSignatureTrait, PublicKey as PK};

const VERSION: &'static [u8; 2] = b"01";

#[derive(PartialEq, Clone, Copy)]
pub struct SignerWallet {
    pk: PublicKey,
    sk: SecretKey,
}

impl Signer for SignerWallet {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        detached_sign(msg, &self.sk).as_bytes().to_vec()
    }
}

impl AddressReader for SignerWallet {
    #[inline]
    fn address(&self) -> String {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend(VERSION.to_vec());
        buf.extend(self.pk.as_bytes());
        let enc = bs58::encode(buf);
        enc.into_string()
    }
}

impl Verifier for SignerWallet {
    fn validate_self(&self, msg: &[u8], sig: &[u8]) -> Result<(), ErrorSecure> {
        if let Ok(ds) = DetachedSignature::from_bytes(sig) {
            return match verify_detached_signature(&ds, msg, &self.pk) {
                Ok(()) => Ok(()),
                Err(_) => Err(ErrorSecure::InvalidCipher),
            };
        }

        Err(ErrorSecure::InvalidSignature)
    }

    fn validate_other(&self, msg: &[u8], sig: &[u8], address: &str) -> Result<(), ErrorSecure> {
        if let Ok(decoded) = bs58::decode(address).into_vec() {
            if !decoded[0..2].eq(VERSION) {
                return Err(ErrorSecure::InvalidPublicKey);
            }
            if let Ok(pk) = PublicKey::from_bytes(&decoded[2..]) {
                if let Ok(ds) = DetachedSignature::from_bytes(&sig) {
                    return match verify_detached_signature(&ds, &msg, &pk) {
                        Ok(()) => Ok(()),
                        Err(_) => Err(ErrorSecure::InvalidCipher),
                    };
                }
            }
        }
        Err(ErrorSecure::InvalidPublicKey)
    }
}

impl SignerVerifierAddressReader for SignerWallet {}

impl SignerWallet {
    #[inline]
    pub fn new() -> Self {
        let (pk, sk) = keypair();
        Self { pk, sk }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct MockData {
        inner: Vec<u8>,
    }

    #[test]
    fn it_should_crypto_sign_the_data() {
        let w = SignerWallet::new();
        for i in (0..=8000).step_by(4000) {
            let mock = MockData { inner: vec![1; i] };
            let v = w.sign(&mock.inner);
            assert_eq!(v.len(), 49856);
        }
    }

    #[test]
    fn it_should_crypto_validate_self_data() {
        let w = SignerWallet::new();
        for i in (0..=8000).step_by(4000) {
            let mock = MockData { inner: vec![1; i] };
            let ds = w.sign(&mock.inner);
            assert_eq!(ds.len(), 49856);

            if let Err(_) = w.validate_self(&mock.inner, &ds) {
                assert_eq!(false, true);
            };
        }
    }

    #[test]
    fn it_should_crypto_validate_other_data() {
        let w = SignerWallet::new();
        for i in (0..=8000).step_by(4000) {
            let mock = MockData { inner: vec![1; i] };
            let v = w.sign(&mock.inner);
            assert_eq!(v.len(), 49856);
        }
    }
}
