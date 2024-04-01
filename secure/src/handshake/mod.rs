use crate::globals::{
    AddressReader, AsVectorBytes, EncapsulatorDecapsulator, EncryptorDecryptor, Signer, Verifier,
};
use crate::randomizer::random_hash;
use digest::{Digest, FixedOutput, OutputSizeUser, Reset};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;

const VERSION: &str = "1.0.0";

const HASH_SUIT: &str = "SHA3_512";
const CIPHER_SING_SUIT: &str = "ED25519";
const CIPHER_ENCAPSULATION_SUIT: &str = "RSA2048";
const Q_CIPHER_SING_SUIT: &str = "SPHINCSSHAKE256FSIMPLE";
const Q_CIPHER_ENCAPSULATION_SUIT: &str = "KYBER1024";

/// ErrorAssignation contains Assignation errors.
///
pub enum ErrorState {
    UnexpectedFailure,
    EntityAlreadyExists,
    SelectedHasherDoesNotExist,
    SelectedSignerDoesNotExist,
    SelectedEncapsulatorDoesNotExist,
    StateNotReset,
    StateNotHello,
    WrongIdPresented,
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
    id: [u8; 32],
    version: String,
    sign_address: Option<String>,
    q_sign_address: Option<String>,
    cipher_address: Option<String>,
    q_cipher_address: Option<String>,
    hash_suits: CipherSuites,
    cipher_suits_sign: CipherSuites,
    cipher_suits_encapsulate: CipherSuites,
    q_cipher_suits_sign: CipherSuites,
    q_cipher_suits_encapsulate: CipherSuites,
}

impl Hello {
    fn new_request(
        id: [u8; 32],
        hash_suite: &[String],
        cipher_suit_sigh: &[String],
        cipher_suits_encapsulate: &[String],
        q_cipher_suits_sign: &[String],
        q_cipher_suits_encapsulate: &[String],
    ) -> Hello {
        Hello {
            id,
            version: VERSION.to_string(),
            sign_address: None,
            q_sign_address: None,
            cipher_address: None,
            q_cipher_address: None,
            hash_suits: CipherSuites::List(hash_suite.to_vec()),
            cipher_suits_sign: CipherSuites::List(cipher_suit_sigh.to_vec()),
            cipher_suits_encapsulate: CipherSuites::List(cipher_suits_encapsulate.to_vec()),
            q_cipher_suits_sign: CipherSuites::List(q_cipher_suits_sign.to_vec()),
            q_cipher_suits_encapsulate: CipherSuites::List(q_cipher_suits_encapsulate.to_vec()),
        }
    }

    fn new_response(
        id: [u8; 32],
        sign_address: String,
        q_sign_address: String,
        cipher_address: String,
        q_cipher_address: String,
        hash_suite: String,
        cipher_suit_sigh: String,
        cipher_suits_encapsulate: String,
        q_cipher_suits_sign: String,
        q_cipher_suits_encapsulate: String,
    ) -> Hello {
        Hello {
            id,
            sign_address: Some(sign_address),
            q_sign_address: Some(q_sign_address),
            cipher_address: Some(cipher_address),
            q_cipher_address: Some(q_cipher_address),
            version: VERSION.to_string(),
            hash_suits: CipherSuites::Selected(hash_suite),
            cipher_suits_sign: CipherSuites::Selected(cipher_suit_sigh),
            cipher_suits_encapsulate: CipherSuites::Selected(cipher_suits_encapsulate),
            q_cipher_suits_sign: CipherSuites::Selected(q_cipher_suits_sign),
            q_cipher_suits_encapsulate: CipherSuites::Selected(q_cipher_suits_encapsulate),
        }
    }

    #[inline]
    fn estimated_size(&self) -> usize {
        let mut size = 0;
        size += self.id.len() + self.version.len();
        for t in [
            &self.sign_address,
            &self.q_sign_address,
            &self.cipher_address,
            &self.q_cipher_address,
        ] {
            match t {
                Some(v) => size += v.len(),
                None => (),
            };
        }
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
        buf.extend(self.id);
        buf.extend(self.version.as_bytes());

        for t in [
            &self.sign_address,
            &self.q_sign_address,
            &self.cipher_address,
            &self.q_cipher_address,
        ] {
            match t {
                Some(v) => buf.extend(v.as_bytes()),
                None => (),
            };
        }

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
#[derive(Debug, Serialize, Deserialize)]
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
        ED: EncapsulatorDecapsulator + AddressReader,
        ECDC: EncryptorDecryptor + AddressReader,
        SA: Signer + AddressReader,
        D: Digest + FixedOutput + Copy,
    >(
        handshake_data: &[u8],
        cipher_public_key: String,
        q_cipher_public_key: String,
        hasher: &D,
        cipher: &ECDC,
        q_cipher: &ED,
        signer: &SA,
        q_signer: &SA,
    ) -> Option<(SecretKeyCiphered, Vec<u8>)> {
        if let Ok((ss, ct)) = q_cipher.encapsulate_shared_key(q_cipher_public_key) {
            if let Ok(ciphertext) = cipher.encrypt(cipher_public_key, &ct) {
                let signature = signer.sign(&ciphertext[..]);
                let q_signature = q_signer.sign(&ciphertext[..]);
                let _ = hasher.chain_update(handshake_data);
                let _ = hasher.chain_update(signer.address().as_bytes());
                let _ = hasher.chain_update(q_signer.address().as_bytes());
                let handshake_hash = hasher.finalize().as_slice().to_vec();
                return Some((
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
        }

        None
    }
}

/// Position describers current handshake state position.
///
#[derive(Debug, Clone, PartialEq, Eq)]
enum Position {
    Reset,
    Hello,
    SharedKey,
}

/// Describes which precedence to choose.
///
#[derive(Debug, Clone, PartialEq, Eq)]
enum Precedence {
    Hash,
    Signer,
    Cipher,
    QSigner,
    QCipher,
}

// TODO: refactor this to get vector of highest ranking protocols in decreasing order.
impl Precedence {
    fn get_precedence(&self) -> String {
        match *self {
            Precedence::Hash => HASH_SUIT.to_owned(),
            Precedence::Cipher => CIPHER_ENCAPSULATION_SUIT.to_owned(),
            Precedence::Signer => CIPHER_SING_SUIT.to_owned(),
            Precedence::QCipher => Q_CIPHER_ENCAPSULATION_SUIT.to_owned(),
            Precedence::QSigner => Q_CIPHER_SING_SUIT.to_owned(),
        }
    }
}

/// State contains handshake state and agreed cryptography and post-quantum cryptography protocols.
/// The task of this entity is to create SecretKey that is in further use to encrypt data exchange between E2E clients.
///
#[derive(Debug, Clone)]
pub struct State<SV, ED, ECDC, D>
where
    SV: Signer + Verifier + AddressReader + Copy,
    ED: EncapsulatorDecapsulator + AddressReader + Copy,
    ECDC: EncryptorDecryptor + AddressReader + Copy,
    D: Digest + OutputSizeUser + FixedOutput + Copy,
{
    id: Option<[u8; 32]>,
    position: Position,
    selected_hasher: Option<String>,
    selected_signer: Option<String>,
    selected_q_signer: Option<String>,
    selected_encapsulator: Option<String>,
    selected_q_encapsulator: Option<String>,
    hashers: HashMap<String, D>,
    signers: HashMap<String, SV>,
    q_signers: HashMap<String, SV>,
    encapsulators: HashMap<String, ECDC>,
    q_encapsulators: HashMap<String, ED>,
    handshake_data: Vec<u8>,
}

impl<SV, ED, ECDC, D> State<SV, ED, ECDC, D>
where
    SV: Signer + Verifier + AddressReader + Copy,
    ED: EncapsulatorDecapsulator + AddressReader + Copy,
    ECDC: EncryptorDecryptor + AddressReader + Copy,
    D: Digest + OutputSizeUser + FixedOutput + Copy,
{
    /// Creates new Assignation entity with empty Cipher Suits.
    ///
    pub fn new() -> State<SV, ED, ECDC, D> {
        State {
            id: None,
            position: Position::Reset,
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
        self.id = None;
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
    pub fn set_encapsulator(&mut self, name: String, ecdc: ECDC) -> Result<(), ErrorState> {
        if self.encapsulators.contains_key(&name) {
            return Err(ErrorState::EntityAlreadyExists);
        }
        let _ = self.encapsulators.insert(name, ecdc);

        Ok(())
    }

    /// Sets encapsulator for post-quantum cryptography cipher suit.
    ///
    pub fn set_q_encapsulator(&mut self, name: String, ed: ED) -> Result<(), ErrorState> {
        if self.q_encapsulators.contains_key(&name) {
            return Err(ErrorState::EntityAlreadyExists);
        }
        let _ = self.q_encapsulators.insert(name, ed);

        Ok(())
    }

    /// Create hello with proposed protocols for the handshake stage 1.
    ///
    pub fn hello_propose(&mut self) -> Option<Hello> {
        if self.position != Position::Reset {
            return None;
        }

        let id_slice = random_hash();
        if id_slice.len() != 32 {
            return None;
        }

        let mut id_arr: [u8; 32] = [0u8; 32];

        for i in 0..id_slice.len() {
            id_arr[i] = id_slice[i];
        }

        let mut hash_suite: Vec<String> = Vec::new();
        let mut cipher_suit_sigh: Vec<String> = Vec::new();
        let mut cipher_suits_encapsulate: Vec<String> = Vec::new();
        let mut q_cipher_suits_sign: Vec<String> = Vec::new();
        let mut q_cipher_suits_encapsulate: Vec<String> = Vec::new();

        for (k, _) in self.hashers.iter() {
            hash_suite.push(k.to_string());
        }
        for (k, _) in self.signers.iter() {
            cipher_suit_sigh.push(k.to_string());
        }
        for (k, _) in self.encapsulators.iter() {
            cipher_suits_encapsulate.push(k.to_string());
        }
        for (k, _) in self.q_signers.iter() {
            q_cipher_suits_sign.push(k.to_string());
        }
        for (k, _) in self.q_encapsulators.iter() {
            q_cipher_suits_encapsulate.push(k.to_string());
        }

        let hello = Hello::new_request(
            id_arr,
            &hash_suite,
            &cipher_suit_sigh,
            &cipher_suits_encapsulate,
            &q_cipher_suits_sign,
            &q_cipher_suits_encapsulate,
        );

        self.id = Some(id_arr);
        self.position = Position::Hello;
        self.handshake_data.extend(hello.as_vector_bytes());

        Some(hello)
    }

    /// Selects protocols.
    ///
    pub fn hello_select(&mut self, hello: &Hello) -> Option<Hello> {
        if self.position != Position::Reset {
            return None;
        }

        let hash = Precedence::Hash.get_precedence();
        let cipher = Precedence::Cipher.get_precedence();
        let signer = Precedence::Signer.get_precedence();
        let q_cipher = Precedence::QCipher.get_precedence();
        let q_signer = Precedence::QSigner.get_precedence();

        if let CipherSuites::List(v) = &hello.hash_suits {
            if !v.contains(&hash) {
                return None;
            }
        }
        if let CipherSuites::List(v) = &hello.cipher_suits_encapsulate {
            if !v.contains(&cipher) {
                return None;
            }
        }
        if let CipherSuites::List(v) = &hello.cipher_suits_sign {
            if !v.contains(&signer) {
                return None;
            }
        }
        if let CipherSuites::List(v) = &hello.q_cipher_suits_encapsulate {
            if !v.contains(&q_cipher) {
                return None;
            }
        }
        if let CipherSuites::List(v) = &hello.q_cipher_suits_sign {
            if !v.contains(&q_signer) {
                return None;
            }
        }

        self.selected_hasher = Some(hash.clone());
        self.selected_signer = Some(signer.clone());
        self.selected_encapsulator = Some(cipher.clone());
        self.selected_q_signer = Some(q_signer.clone());
        self.selected_q_encapsulator = Some(q_cipher.clone());
        self.position = Position::Hello;
        self.id = Some(hello.id);
        self.handshake_data.extend(&hello.as_vector_bytes());

        let hello_response = Hello::new_response(
            hello.id,
            hello.sign_address.clone()?,
            hello.q_sign_address.clone()?,
            hello.cipher_address.clone()?,
            hello.q_cipher_address.clone()?,
            hash.clone(),
            signer.to_owned(),
            cipher.to_owned(),
            q_signer.to_owned(),
            q_cipher.to_owned(),
        );

        self.handshake_data.extend(hello_response.as_vector_bytes());

        Some(hello_response)
    }

    pub fn hello_selected_to_cipher(
        &mut self,
        hello: &Hello,
    ) -> Option<(SecretKeyCiphered, Vec<u8>)> {
        if self.position != Position::Hello {
            return None;
        }

        self.handshake_data.extend(hello.as_vector_bytes());

        if let CipherSuites::Selected(hash) = hello.hash_suits.borrow() {
            if let Some(_) = self.hashers.get(hash) {
                self.selected_hasher = Some(hash.clone());
            } else {
                return None;
            }
        } else {
            return None;
        }

        if let CipherSuites::Selected(signer) = hello.cipher_suits_sign.borrow() {
            if let Some(_) = self.signers.get(signer) {
                self.selected_signer = Some(signer.clone());
            } else {
                return None;
            }
        } else {
            return None;
        }

        if let CipherSuites::Selected(signer) = hello.q_cipher_suits_sign.borrow() {
            if let Some(_) = self.q_signers.get(signer) {
                self.selected_q_signer = Some(signer.clone());
            } else {
                return None;
            }
        } else {
            return None;
        }

        if let CipherSuites::Selected(cipher) = hello.cipher_suits_encapsulate.borrow() {
            if let Some(_) = self.encapsulators.get(cipher) {
                self.selected_signer = Some(cipher.clone());
            } else {
                return None;
            }
        } else {
            return None;
        }

        if let CipherSuites::Selected(cipher) = hello.q_cipher_suits_encapsulate.borrow() {
            if let Some(_) = self.q_encapsulators.get(cipher) {
                self.selected_encapsulator = Some(cipher.clone());
            } else {
                return None;
            }
        } else {
            return None;
        }

        self.position = Position::SharedKey;

        let ca = hello.cipher_address.clone()?;
        let q_ca = hello.q_cipher_address.clone()?;

        SecretKeyCiphered::from_ciphers_with_secret(
            &self.handshake_data,
            ca,
            q_ca,
            self.hashers.get(&self.selected_hasher.clone()?)?,
            self.encapsulators
                .get(&self.selected_encapsulator.clone()?)?,
            self.q_encapsulators
                .get(&self.selected_q_encapsulator.clone()?)?,
            self.signers.get(&self.selected_signer.clone()?)?,
            self.q_signers.get(&self.selected_q_signer.clone()?)?,
        )
    }
}
