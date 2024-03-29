use crate::globals::{
    AddressReader, AsVectorBytes, EncapsulatorDecapsulator, EncryptorDecryptor, Signer, Verifier,
};
use digest::{Digest, OutputSizeUser};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use std::collections::HashMap;
use std::hash::Hash;

const VERSION: &str = "1.0.0";

/// ErrorAssignation contains Assignation errors.
///
pub enum ErrorState {
    UnexpectedFailure,
    EntityAlreadyExists,
    SelectedSignerDoesNotExist,
    SelectedEncapsulatorDoesNotExist,
    StateNotReset,
}

/// CipherSuits contains list of cipher suits or selected cipher suit for the ephemeral key exchange.
///
#[derive(Serialize, Deserialize, Hash)]
enum CipherSuites {
    List(Vec<String>),
    Selected(String),
}

/// Hello message allows to agree cipher suits that will be used to create E2E ephemeral key
/// exchange between E2E clients with selected cipher suit.
///  
#[derive(Serialize, Deserialize)]
pub struct Hello {
    client_name: String,
    version: String,
    hash_suits: CipherSuites,
    cipher_suits_sign: CipherSuites,
    cipher_suits_encapsulate: CipherSuites,
    q_cipher_suits_sign: CipherSuites,
    q_cipher_suits_encapsulate: CipherSuites,
}

impl Hello {
    #[inline]
    fn estimated_size(&self) -> usize {
        let mut size = 0;
        size += self.client_name.len() + self.version.len();
        for t in [
            &self.hash_suits,
            &self.cipher_suits_sign,
            &self.cipher_suits_encapsulate,
            &self.q_cipher_suits_sign,
            &self.q_cipher_suits_encapsulate,
        ] {
            match t {
                CipherSuites::List(set) => {
                    for i in set.iter() {
                        size += i.len();
                    }
                }
                CipherSuites::Selected(selected) => {
                    size += selected.len();
                }
            };
        }
        size
    }
}

impl AsVectorBytes for Hello {
    #[inline]
    fn as_vector_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(self.estimated_size());
        buf.extend(self.client_name.as_bytes());
        buf.extend(self.version.as_bytes());
        for t in [
            &self.hash_suits,
            &self.cipher_suits_sign,
            &self.cipher_suits_encapsulate,
            &self.q_cipher_suits_sign,
            &self.q_cipher_suits_encapsulate,
        ] {
            match t {
                CipherSuites::List(set) => {
                    for i in set.iter() {
                        buf.extend(i.as_bytes());
                    }
                }
                CipherSuites::Selected(selected) => {
                    buf.extend(selected.as_bytes());
                }
            };
        }

        buf
    }
}

/// PublicKey is a set of ephemeral keys to generate SecretKey used in the future encryption between E2E clients.
///
#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    name: String,
    pk_encapsulate: Vec<u8>,
    pk_sign: Vec<u8>,
    signature: Vec<u8>,
    q_pk_encapsulate: Vec<u8>,
    q_pk_sign: Vec<u8>,
    q_signature: Vec<u8>,
}

impl PublicKey {
    #[inline]
    fn estimated_size(&self) -> usize {
        let mut size: usize = self.name.len();
        size += self.pk_encapsulate.len() + self.pk_sign.len() + self.signature.len();
        size += self.q_pk_encapsulate.len() + self.q_pk_sign.len() + self.q_signature.len();
        size
    }
}

impl AsVectorBytes for PublicKey {
    #[inline]
    fn as_vector_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(self.estimated_size());
        buf.extend(self.name.as_bytes());
        buf.extend(self.pk_encapsulate.iter());
        buf.extend(self.pk_sign.iter());
        buf.extend(self.signature.iter());
        buf.extend(self.q_pk_encapsulate.iter());
        buf.extend(self.q_pk_sign.iter());
        buf.extend(self.q_signature.iter());

        buf
    }
}

/// Secret key is a ciphered message established for the encryption session between E2E clients.
/// All the future messages are encrypted with the SecretKey.
///
#[derive(Serialize, Deserialize)]
pub struct SecretKeyCiphered {
    handshake_hash: Vec<u8>,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
    q_signature: Vec<u8>,
    address: String,
    q_address: String,
}

impl SecretKeyCiphered {
    pub fn from_ciphers_with_secret<
        EDA: EncryptorDecryptor + AddressReader,
        SA: Signer + AddressReader,
    >(
        handshake_hash: Vec<u8>,
        handshaker_public_key: String,
        cipher: EDA,
        q_cipher: &dyn EncapsulatorDecapsulator,
        signer: SA,
        q_signer: SA,
    ) -> Result<(SecretKeyCiphered, Vec<u8>), ErrorState> {
        if let Ok((ss, ct)) = q_cipher.encapsulate_shared_key(handshaker_public_key) {
            if let Ok(ciphertext) = cipher.encrypt(cipher.address(), &ct) {
                let signature = signer.sign(&ciphertext[..]);
                let q_signature = q_signer.sign(&ciphertext[..]);

                return Ok((
                    SecretKeyCiphered {
                        handshake_hash,
                        ciphertext: ciphertext,
                        signature,
                        q_signature,
                        address: signer.address(),
                        q_address: q_signer.address(),
                    },
                    ss,
                ));
            }
        } else {
            return Err(ErrorState::UnexpectedFailure);
        };

        Err(ErrorState::UnexpectedFailure)
    }
}

/// State contains handshake state and agreed cryptography and post-quantum cryptography protocols.
/// The task of this entity is to create SecretKey that is in further use to encrypt data exchange between E2E clients.
///
pub struct State<SV, ED, ECDC, D>
where
    SV: Signer + Verifier,
    ED: EncapsulatorDecapsulator,
    ECDC: EncryptorDecryptor,
    D: Digest,
{
    selected_name: Option<String>,
    selected_hasher: Option<String>,
    selected_signer: Option<String>,
    selected_q_signer: Option<String>,
    selected_encapsulator: Option<String>,
    selected_q_encapsulator: Option<String>,
    hashers: HashMap<String, D>,
    signers: HashMap<String, SV>,
    q_signers: HashMap<String, SV>,
    encapsulators: HashMap<String, ED>,
    q_encapsulators: HashMap<String, ECDC>,
    handshake_data: Vec<u8>,
}

impl<SV, ED, ECDC, D> State<SV, ED, ECDC, D>
where
    SV: Signer + Verifier,
    ED: EncapsulatorDecapsulator,
    ECDC: EncryptorDecryptor,
    D: Digest + OutputSizeUser,
{
    /// Creates new Assignation entity with empty Cipher Suits.
    ///
    pub fn new() -> State<SV, ED, ECDC, D> {
        State {
            selected_name: None,
            selected_hasher: None,
            selected_signer: None,
            selected_q_signer: None,
            selected_encapsulator: None,
            selected_q_encapsulator: None,
            hashers: HashMap::new(),
            signers: HashMap::new(),
            q_signers: HashMap::new(),
            encapsulators: HashMap::new(),
            q_encapsulators: HashMap::new(),
            handshake_data: Vec::new(),
        }
    }

    /// Resets selected hashers, signers and encapsulators, cleans the handshake data.
    /// This method allows to reset the entity before reusing it,
    /// but all cipher suits are still in the hashmaps ready to be used.
    ///
    pub fn reset(&mut self) {
        self.selected_name = None;
        self.selected_hasher = None;
        self.selected_signer = None;
        self.selected_q_signer = None;
        self.selected_encapsulator = None;
        self.selected_q_encapsulator = None;
        self.handshake_data = Vec::new();
    }

    /// Sets hasher cipher suit.
    ///
    pub fn set_hasher(&mut self, name: String, d: D) -> Result<(), ErrorState> {
        if self.hashers.contains_key(&name) {
            return Err(ErrorState::EntityAlreadyExists);
        }
        let _ = self.hashers.insert(name, d);

        Ok(())
    }

    /// Sets signer for pre-quantum cryptography cipher suit.
    ///
    pub fn set_signer(&mut self, name: String, s: SV) -> Result<(), ErrorState> {
        if self.signers.contains_key(&name) {
            return Err(ErrorState::EntityAlreadyExists);
        }
        let _ = self.signers.insert(name, s);

        Ok(())
    }

    /// Sets signer for post-quantum cryptography cipher suit.
    ///
    pub fn set_q_signer(&mut self, name: String, s: SV) -> Result<(), ErrorState> {
        if self.q_signers.contains_key(&name) {
            return Err(ErrorState::EntityAlreadyExists);
        }
        let _ = self.q_signers.insert(name, s);

        Ok(())
    }

    /// Sets encapsulator for pre-quantum cryptography cipher suit.
    ///
    pub fn set_encapsulator(&mut self, name: String, s: ED) -> Result<(), ErrorState> {
        if self.encapsulators.contains_key(&name) {
            return Err(ErrorState::EntityAlreadyExists);
        }
        let _ = self.encapsulators.insert(name, s);

        Ok(())
    }

    /// Sets encapsulator for post-quantum cryptography cipher suit.
    ///
    pub fn set_q_encapsulator(&mut self, name: String, ecdc: ECDC) -> Result<(), ErrorState> {
        if self.q_encapsulators.contains_key(&name) {
            return Err(ErrorState::EntityAlreadyExists);
        }
        let _ = self.q_encapsulators.insert(name, ecdc);

        Ok(())
    }

    /// Selects hasher cipher suit.
    ///
    pub fn select_hasher(&mut self, name: String) -> Result<&D, ErrorState> {
        if let Some(h) = self.hashers.get(&name) {
            self.selected_hasher = Some(name);
            return Ok(h);
        }

        Err(ErrorState::SelectedSignerDoesNotExist)
    }

    /// Selects signer for pre-quantum cryptography cipher suit.
    ///
    pub fn select_signer(&mut self, name: String) -> Result<&SV, ErrorState> {
        if let Some(sv) = self.signers.get(&name) {
            self.selected_signer = Some(name);
            return Ok(sv);
        }

        Err(ErrorState::SelectedSignerDoesNotExist)
    }

    /// Selects signer for post-quantum cryptography cipher suit.
    ///
    pub fn select_q_signer(&mut self, name: String) -> Result<&SV, ErrorState> {
        if let Some(sv) = self.q_signers.get(&name) {
            self.selected_q_signer = Some(name);
            return Ok(sv);
        }

        Err(ErrorState::SelectedSignerDoesNotExist)
    }

    /// Selects encapsulator for pre-quantum cryptography cipher suit.
    ///
    pub fn select_encapsulator(&mut self, name: String) -> Result<&ED, ErrorState> {
        if let Some(ed) = self.encapsulators.get(&name) {
            self.selected_encapsulator = Some(name);
            return Ok(ed);
        }

        Err(ErrorState::SelectedSignerDoesNotExist)
    }

    /// Selects encapsulator for post-quantum cryptography cipher suit.
    ///
    pub fn select_q_encapsulator(&mut self, name: String) -> Result<&ECDC, ErrorState> {
        if let Some(ecdc) = self.q_encapsulators.get(&name) {
            self.selected_q_encapsulator = Some(name);
            return Ok(ecdc);
        }

        Err(ErrorState::SelectedSignerDoesNotExist)
    }

    //   pub fn hello(&self) -> Result<Hello, ErrorState> {
    //       if let Some(_) = self.selected_name {
    //           return Err(ErrorState::StateNotReset);
    //       }

    //       Some(Hello {})
    //   }
}

//fn random_hash() -> &[u8] {
//    let mut rng = rand::thread_rng();
//    let hash_size = ;
//    let mut random_bytes = vec![0; hash_size];
//    rng.fill(&mut random_bytes);
//
//    let mut hasher = Sha256::new();
//    hasher.input(&random_bytes);
//    hasher.result()
//}
