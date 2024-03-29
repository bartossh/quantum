use crate::globals::{
    AddressReader, AsVectorBytes, EncapsulatorDecapsulator, EncryptorDecryptor, Signer, Verifier,
};
use crate::randomizer::random_hash;
use digest::{Digest, OutputSizeUser};
use serde::{Deserialize, Serialize};
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
            hash_suits: CipherSuites::List(hash_suite.to_vec()),
            cipher_suits_sign: CipherSuites::List(cipher_suit_sigh.to_vec()),
            cipher_suits_encapsulate: CipherSuites::List(cipher_suits_encapsulate.to_vec()),
            q_cipher_suits_sign: CipherSuites::List(q_cipher_suits_sign.to_vec()),
            q_cipher_suits_encapsulate: CipherSuites::List(q_cipher_suits_encapsulate.to_vec()),
        }
    }

    fn new_response(
        id: [u8; 32],
        hash_suite: String,
        cipher_suit_sigh: String,
        cipher_suits_encapsulate: String,
        q_cipher_suits_sign: String,
        q_cipher_suits_encapsulate: String,
    ) -> Hello {
        Hello {
            id,
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

/// Position describers current handshake state position.
///
#[derive(Debug, Clone, PartialEq, Eq)]
enum Position {
    Reset,
    Hello,
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
    SV: Signer + Verifier,
    ED: EncapsulatorDecapsulator,
    ECDC: EncryptorDecryptor,
    D: Digest,
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

    /// Create hello with proposed protocols for the handshake stage 1.
    ///
    pub fn hello_propose(&mut self) -> Result<Hello, ErrorState> {
        if self.position != Position::Reset {
            return Err(ErrorState::StateNotReset);
        }

        let id_slice = random_hash();
        if id_slice.len() != 32 {
            return Err(ErrorState::UnexpectedFailure);
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

        Ok(hello)
    }

    /// Create hello selected protocols.
    ///
    pub fn hello_selected(&mut self, hello: &Hello) -> Result<Hello, ErrorState> {
        if self.position != Position::Reset {
            return Err(ErrorState::StateNotReset);
        }

        let hash = Precedence::Hash.get_precedence();
        let cipher = Precedence::Cipher.get_precedence();
        let signer = Precedence::Signer.get_precedence();
        let q_cipher = Precedence::QCipher.get_precedence();
        let q_signer = Precedence::QSigner.get_precedence();

        if let CipherSuites::List(v) = &hello.hash_suits {
            if !v.contains(&hash) {
                return Err(ErrorState::SelectedHasherDoesNotExist);
            }
        }
        if let CipherSuites::List(v) = &hello.cipher_suits_encapsulate {
            if !v.contains(&cipher) {
                return Err(ErrorState::SelectedHasherDoesNotExist);
            }
        }
        if let CipherSuites::List(v) = &hello.cipher_suits_sign {
            if !v.contains(&signer) {
                return Err(ErrorState::SelectedHasherDoesNotExist);
            }
        }
        if let CipherSuites::List(v) = &hello.q_cipher_suits_encapsulate {
            if !v.contains(&q_cipher) {
                return Err(ErrorState::SelectedHasherDoesNotExist);
            }
        }
        if let CipherSuites::List(v) = &hello.q_cipher_suits_sign {
            if !v.contains(&q_signer) {
                return Err(ErrorState::SelectedHasherDoesNotExist);
            }
        }

        let hello_response = Hello::new_response(
            hello.id,
            hash.to_owned(),
            signer.to_owned(),
            cipher.to_owned(),
            q_signer.to_owned(),
            q_cipher.to_owned(),
        );

        self.selected_hasher = Some(hash);
        self.selected_signer = Some(signer);
        self.selected_encapsulator = Some(cipher);
        self.selected_q_signer = Some(q_signer);
        self.selected_q_encapsulator = Some(q_cipher);
        self.position = Position::Hello;
        self.id = Some(hello.id);
        self.handshake_data.extend(&hello.as_vector_bytes());
        self.handshake_data.extend(hello_response.as_vector_bytes());

        Ok(hello_response)
    }
}
