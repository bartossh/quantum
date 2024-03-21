use crate::traits::{AsVecBytes, Signer, Verifier};
use pqcrypto::sign::sphincsshake256fsimple::{
    detached_sign, keypair, verify_detached_signature, DetachedSignature, PublicKey, SecretKey,
};
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as PK, VerificationError,
};

const VERSION: &'static [u8; 2] = b"01";

#[derive(PartialEq, Clone, Copy)]
pub struct Wallet {
    pk: PublicKey,
    sk: SecretKey,
}

impl Signer for Wallet {
    fn sign(&self, msg: &dyn AsVecBytes) -> Vec<u8> {
        let data: &[u8] = &msg.as_vec_bytes()[..];
        detached_sign(data, &self.sk).as_bytes().to_vec()
    }

    fn address(&self) -> String {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend(VERSION.to_vec());
        buf.extend(self.pk.as_bytes());
        let enc = bs58::encode(buf);
        enc.into_string()
    }
}

impl Verifier for Wallet {
    fn validate_self(&self, msg: &dyn AsVecBytes, sig: Vec<u8>) -> Result<(), VerificationError> {
        let data: &[u8] = &msg.as_vec_bytes()[..];
        if let Ok(ds) = DetachedSignature::from_bytes(&sig[..]) {
            return verify_detached_signature(&ds, data, &self.pk);
        }

        Err(VerificationError::InvalidSignature)
    }

    fn validate_other(
        &self,
        msg: &dyn AsVecBytes,
        sig: &Vec<u8>,
        address: &str,
    ) -> Result<(), VerificationError> {
        if let Ok(decoded) = bs58::decode(address).into_vec() {
            if !decoded[0..2].eq(VERSION) {
                return Err(VerificationError::InvalidSignature);
            }
            if let Ok(pk) = PublicKey::from_bytes(&decoded[2..]) {
                let data: &[u8] = &msg.as_vec_bytes()[..];
                if let Ok(ds) = DetachedSignature::from_bytes(&sig[..]) {
                    return verify_detached_signature(&ds, data, &pk);
                }
            }
        }
        Err(VerificationError::InvalidSignature)
    }
}

impl Wallet {
    #[inline]
    pub fn new() -> Wallet {
        let (pk, sk) = keypair();
        Wallet { pk, sk }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct MockAsVectorBytes {
        inner: Vec<u8>,
    }
    impl AsVecBytes for MockAsVectorBytes {
        fn as_vec_bytes(&self) -> Vec<u8> {
            self.inner.clone()
        }
    }

    #[test]
    fn crypto_sign() {
        let w = Wallet::new();
        for i in (0..=8000).step_by(4000) {
            let mock = MockAsVectorBytes { inner: vec![1; i] };
            let v = w.sign(&mock);
            assert_eq!(v.len(), 49856);
        }
    }

    #[test]
    fn crypto_validate_self() {
        let w = Wallet::new();
        for i in (0..=8000).step_by(4000) {
            let mock = MockAsVectorBytes { inner: vec![1; i] };
            let ds = w.sign(&mock);
            assert_eq!(ds.len(), 49856);

            if let Err(_) = w.validate_self(&mock, ds) {
                assert_eq!(false, true);
            };
        }
    }

    #[test]
    fn crypto_validate_other() {
        let w = Wallet::new();
        for i in (0..=8000).step_by(4000) {
            let mock = MockAsVectorBytes { inner: vec![1; i] };
            let v = w.sign(&mock);
            assert_eq!(v.len(), 49856);
        }
    }
}
