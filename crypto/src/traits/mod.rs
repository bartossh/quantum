use pqcrypto_traits::sign::VerificationError;

pub trait AsVecBytes {
    fn as_vec_bytes(&self) -> Vec<u8>;
}

/// Signer signs the message returning DetachedSignature.
pub trait Signer {
    fn sign(&self, msg: &dyn AsVecBytes) -> Vec<u8>;
    fn address(&self) -> String;
}

/// Validator validates the massage against the DetachedSignature.
pub trait Verifier {
    fn validate_self(&self, msg: &dyn AsVecBytes, sig: Vec<u8>) -> Result<(), VerificationError>;
    fn validate_other(
        &self,
        msg: &dyn AsVecBytes,
        sig: &Vec<u8>,
        address: &str,
    ) -> Result<(), VerificationError>;
}

/// Errors describing EncryptDecrypter failures.
#[derive(Debug)]
pub enum ErrorEncryptDecrypt {
    InvalidPublicKey,
    InvalidCipher,
}

/// EncryptDecrypter generates shared key and encrypts and decrypts the shared key.
pub trait EncapsulatorDecapsulator {
    fn encapsulate_shared_key(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ErrorEncryptDecrypt>;
    fn decapsulate_shared_key(&self, cipher: &[u8]) -> Result<Vec<u8>, ErrorEncryptDecrypt>;
}
