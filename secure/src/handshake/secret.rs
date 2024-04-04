use crate::asymmetric_pre_quant_cipher::CipherWallet;
use crate::asymmetric_pre_quant_signer::SignerWallet;
use crate::asymmetric_quant_cipher::SharedKeyGeneratorWallet;
use crate::asymmetric_quant_signer::SignerWallet as QSignerWallet;
use crate::globals::{
    EncapsulatorDecapsulatorAddressReader, EncryptorDecryptorAddressReader, ErrorSecure, Hasher,
    SignerVerifierAddressReader,
};
use crate::sha3_hasher::HashSha3_512;
use enum_iterator::Sequence;
use serde::{Deserialize, Serialize};

/// Secret key is a ciphered message established for the encryption session between E2E clients.
/// /// All the future messages are encrypted with the SecretKey.
///
#[derive(Debug, Serialize, Deserialize)]
pub struct Cipher {
    pub handshake_hash: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
    pub q_signature: Vec<u8>,
    pub address: String,
    pub q_address: String,
}

#[derive(Debug, PartialEq, Sequence, Serialize, Deserialize, Clone, Copy)]
#[repr(u8)]
pub enum HashSuite {
    Sha3_512,
}

#[derive(Debug, PartialEq, Sequence, Serialize, Deserialize, Clone, Copy)]
#[repr(u8)]
pub enum CipherSuite {
    RSA2048,
}

#[derive(Debug, PartialEq, Sequence, Serialize, Deserialize, Clone, Copy)]
#[repr(u8)]
pub enum SignerSuite {
    ED25519,
}

#[derive(Debug, PartialEq, Sequence, Serialize, Deserialize, Clone, Copy)]
#[repr(u8)]
pub enum QCipherSuite {
    KYBER1024,
}

#[derive(Debug, PartialEq, Sequence, Serialize, Deserialize, Clone, Copy)]
#[repr(u8)]
pub enum QSignerSuite {
    SPHINCSSHAKE256FSIMPLE,
}

/// CipherCreator allows to create cipher for shared key.
///
pub struct CipherCreator {
    hasher: Box<dyn Hasher>,
    signer_verifier: Box<dyn SignerVerifierAddressReader>,
    q_signer_verifier: Box<dyn SignerVerifierAddressReader>,
    encryptor_decryptor: Box<dyn EncryptorDecryptorAddressReader>,
    q_encapsulator_decapsulator: Box<dyn EncapsulatorDecapsulatorAddressReader>,
}

impl CipherCreator {
    pub fn with_params(
        h: HashSuite,
        c: CipherSuite,
        s: SignerSuite,
        qc: QCipherSuite,
        qs: QSignerSuite,
    ) -> Result<Self, ErrorSecure> {
        let cc = Self {
            hasher: create_hasher(h),
            signer_verifier: create_signer(s),
            q_signer_verifier: create_q_signer(qs),
            encryptor_decryptor: create_cipher(c)?,
            q_encapsulator_decapsulator: create_q_cipher(qc),
        };

        Ok(cc)
    }

    /// Returns addresses in order (signer, q signer, encryptor, q encapsulator).
    ///
    pub fn addresses(&self) -> (String, String, String, String) {
        (
            self.signer_verifier.address(),
            self.q_signer_verifier.address(),
            self.encryptor_decryptor.address(),
            self.q_encapsulator_decapsulator.address(),
        )
    }

    /// Creates shared key and packs given data to the Cipher.
    ///
    pub fn pack_to_cipher(
        &mut self,
        data: &[u8],
        cipher_address: String,
        q_cipher_address: String,
    ) -> Result<(Vec<u8>, Cipher), ErrorSecure> {
        let (shared_key, ciphertext) = self
            .q_encapsulator_decapsulator
            .encapsulate_shared_key(q_cipher_address)?;
        let hash = self.hasher.hash_reset(data);
        Ok((
            shared_key,
            Cipher {
                handshake_hash: hash.clone(),
                ciphertext: self
                    .encryptor_decryptor
                    .encrypt(cipher_address, &ciphertext)?,
                signature: self.signer_verifier.sign(&hash),
                q_signature: self.q_signer_verifier.sign(&hash),
                address: self.signer_verifier.address(),
                q_address: self.q_signer_verifier.address(),
            },
        ))
    }

    /// Unpacks shared key from Cipher.
    ///
    pub fn unpack_from_cipher(
        &mut self,
        cipher: &Cipher,
        data: &[u8],
    ) -> Result<Vec<u8>, ErrorSecure> {
        let hash = self.hasher.hash_reset(data);
        if &cipher.handshake_hash != &hash {
            return Err(ErrorSecure::InvalidHash);
        }

        self.signer_verifier.validate_other(
            &cipher.handshake_hash,
            &cipher.signature,
            &cipher.address,
        )?;

        self.q_signer_verifier.validate_other(
            &cipher.handshake_hash,
            &cipher.q_signature,
            &cipher.q_address,
        )?;

        let middle_way_sharedkey = self.encryptor_decryptor.decrypt(&cipher.ciphertext)?;

        self.q_encapsulator_decapsulator
            .decapsulate_shared_key(&middle_way_sharedkey)
    }
}

fn create_hasher(h: HashSuite) -> Box<impl Hasher> {
    match h {
        HashSuite::Sha3_512 => Box::new(HashSha3_512::new()),
    }
}

fn create_signer(s: SignerSuite) -> Box<impl SignerVerifierAddressReader> {
    match s {
        SignerSuite::ED25519 => Box::new(SignerWallet::new()),
    }
}

fn create_q_signer(s: QSignerSuite) -> Box<impl SignerVerifierAddressReader> {
    match s {
        QSignerSuite::SPHINCSSHAKE256FSIMPLE => Box::new(QSignerWallet::new()),
    }
}

fn create_cipher(c: CipherSuite) -> Result<Box<impl EncryptorDecryptorAddressReader>, ErrorSecure> {
    match c {
        CipherSuite::RSA2048 => match CipherWallet::new() {
            Ok(cw) => Ok(Box::new(cw)),
            Err(_) => Err(ErrorSecure::UnexpectedFailure),
        },
    }
}

fn create_q_cipher(c: QCipherSuite) -> Box<impl EncapsulatorDecapsulatorAddressReader> {
    match c {
        QCipherSuite::KYBER1024 => Box::new(SharedKeyGeneratorWallet::new()),
    }
}
