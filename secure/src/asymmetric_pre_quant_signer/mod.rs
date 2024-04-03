use crate::globals::SignerVerifierAddressReader;
use crate::globals::{AddressReader, ErrorSignerVerifier, Signer, Verifier};
use ed25519_dalek::ed25519::SignatureBytes;
use ed25519_dalek::Digest;
use ed25519_dalek::Signature;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha3::Sha3_512;

const VERSION: &'static [u8; 2] = b"01";

/// CONTEXT explained.
/// It is generally a good idea to choose a context and try to make it unique to your project and this specific usage of signatures.
/// For example, without this, if you were to convert your OpenPGP key to a Bitcoin key
/// (just as an example, and also Don’t Ever Do That) and someone tricked you into signing an “email” which was actually a Bitcoin transaction moving all your magic internet money to their address, it’d be a valid transaction.
/// By adding a context, this trick becomes impossible,
/// because the context is concatenated into the hash, which is then signed. So, going with the previous example,
/// if your bitcoin wallet used a context of “BitcoinWalletAppTxnSigning” and OpenPGP used a context
/// (this is likely the least of their safety problems) of “GPGsCryptoIsntConstantTimeLol”,
/// then the signatures produced by both could never match the other,
/// even if they signed the exact same message with the same key.
///
const CONTEXT: &'static [u8; 36] = b"Ed25519DalekSignQuantumCryptoContext";

#[derive(Debug)]
pub struct SignerWallet {
    signing_key: SigningKey,
}

impl SignerWallet {
    #[inline]
    pub fn new() -> SignerWallet {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        SignerWallet { signing_key }
    }
}

impl AddressReader for SignerWallet {
    #[inline]
    fn address(&self) -> String {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend(VERSION.to_vec());
        buf.extend(self.signing_key.verifying_key().as_bytes());
        let enc = bs58::encode(buf);
        enc.into_string()
    }
}

impl Signer for SignerWallet {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let mut prehashed: Sha3_512 = Sha3_512::new();
        prehashed.update(msg);
        if let Ok(sig) = self.signing_key.sign_prehashed(prehashed, Some(CONTEXT)) {
            return sig.to_bytes().to_vec();
        }

        Vec::new()
    }
}

impl Verifier for SignerWallet {
    fn validate_self(&self, msg: &[u8], sig: &[u8]) -> Result<(), ErrorSignerVerifier> {
        let mut prehashed: Sha3_512 = Sha3_512::new();
        prehashed.update(msg);
        if let Ok(signature_bytes) = SignatureBytes::try_from(sig) {
            let sig = Signature::from_bytes(&signature_bytes as &SignatureBytes);
            if let Ok(_) =
                self.signing_key
                    .verifying_key()
                    .verify_prehashed(prehashed, Some(CONTEXT), &sig)
            {
                return Ok(());
            }
        }

        Err(ErrorSignerVerifier::InvalidSignature)
    }

    fn validate_other(
        &self,
        msg: &[u8],
        sig: &[u8],
        address: &str,
    ) -> Result<(), ErrorSignerVerifier> {
        if let Ok(decoded) = bs58::decode(address).into_vec() {
            if !decoded[0..2].eq(VERSION) {
                return Err(ErrorSignerVerifier::InvalidPublicKey);
            }
            if decoded[2..].len() != 32 {
                return Err(ErrorSignerVerifier::InvalidPublicKey);
            }
            let mut verifying_key_bytes: [u8; 32] = [0; 32];
            for (i, v) in decoded[2..].iter().enumerate() {
                verifying_key_bytes[i] = *v;
            }

            if let Ok(verifying_key) = VerifyingKey::from_bytes(&verifying_key_bytes) {
                let mut prehashed: Sha3_512 = Sha3_512::new();
                prehashed.update(msg);
                if let Ok(signature_bytes) = SignatureBytes::try_from(sig) {
                    let sig = Signature::from_bytes(&signature_bytes as &SignatureBytes);
                    if let Ok(_) = verifying_key.verify_prehashed(prehashed, Some(CONTEXT), &sig) {
                        return Ok(());
                    }
                }
            }
        }
        Err(ErrorSignerVerifier::InvalidSignature)
    }
}

impl SignerVerifierAddressReader for SignerWallet {}

#[cfg(test)]
mod tests {
    use super::*;
    struct MockData {
        inner: Vec<u8>,
    }

    #[test]
    fn crypto_sign() {
        let w = SignerWallet::new();
        for i in (0..=8000).step_by(4000) {
            let mock = MockData { inner: vec![1; i] };
            let v = w.sign(&mock.inner);
            assert_eq!(v.len(), 64);
        }
    }

    #[test]
    fn crypto_validate_self() {
        let w = SignerWallet::new();
        for i in (0..=8000).step_by(4000) {
            let mock = MockData { inner: vec![1; i] };
            let ds = w.sign(&mock.inner);
            assert_eq!(ds.len(), 64);

            if let Err(_) = w.validate_self(&mock.inner, &ds) {
                assert_eq!(false, true);
            };
        }
    }

    #[test]
    fn crypto_validate_other() {
        let w = SignerWallet::new();
        for i in (0..=8000).step_by(4000) {
            let mock = MockData { inner: vec![1; i] };
            let v = w.sign(&mock.inner);
            assert_eq!(v.len(), 64);
        }
    }
}
