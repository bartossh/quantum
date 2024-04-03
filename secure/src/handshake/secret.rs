use crate::asymmetric_pre_quant_cipher::CipherWallet;
use crate::asymmetric_pre_quant_signer::SignerWallet;
use crate::asymmetric_quant_cipher::SharedKeyGeneratorWallet;
use crate::asymmetric_quant_signer::SignerWallet as QSignerWallet;
use crate::globals::{
    EncapsulatorDecapsulatorAddressReader, EncryptorDecryptorAddressReader, Hasher,
    SignerVerifierAddressReader,
};
use crate::sha3_hasher::HashSha3_512;
use enum_iterator::Sequence;
use serde::{Deserialize, Serialize};

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
    ) -> Result<Self, ()> {
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
}

fn create_hasher(h: HashSuite) -> Box<dyn Hasher> {
    match h {
        HashSuite::Sha3_512 => Box::new(HashSha3_512::new()),
    }
}

fn create_signer(s: SignerSuite) -> Box<dyn SignerVerifierAddressReader> {
    match s {
        SignerSuite::ED25519 => Box::new(SignerWallet::new()),
    }
}

fn create_q_signer(s: QSignerSuite) -> Box<dyn SignerVerifierAddressReader> {
    match s {
        QSignerSuite::SPHINCSSHAKE256FSIMPLE => Box::new(QSignerWallet::new()),
    }
}

fn create_cipher(c: CipherSuite) -> Result<Box<dyn EncryptorDecryptorAddressReader>, ()> {
    match c {
        CipherSuite::RSA2048 => match CipherWallet::new() {
            Ok(cw) => Ok(Box::new(cw)),
            Err(_) => Err(()),
        },
    }
}

fn create_q_cipher(c: QCipherSuite) -> Box<dyn EncapsulatorDecapsulatorAddressReader> {
    match c {
        QCipherSuite::KYBER1024 => Box::new(SharedKeyGeneratorWallet::new()),
    }
}

/// Secret key is a ciphered message established for the encryption session between E2E clients.
/// All the future messages are encrypted with the SecretKey.
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
