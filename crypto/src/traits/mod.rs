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
