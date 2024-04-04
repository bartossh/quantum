mod secret;
use crate::globals::{AsVectorBytes, ErrorSecure};
use crate::randomizer::random_hash;
use enum_iterator::all;
use serde::{Deserialize, Serialize};
use std::result::Result;

const VERSION: &str = "1.0.0";

fn get_precedence(
    hs: &[secret::HashSuite],
    cs: &[secret::CipherSuite],
    qcs: &[secret::QCipherSuite],
    ss: &[secret::SignerSuite],
    qss: &[secret::QSignerSuite],
) -> Result<
    (
        secret::HashSuite,
        secret::CipherSuite,
        secret::QCipherSuite,
        secret::SignerSuite,
        secret::QSignerSuite,
    ),
    (),
> {
    let mut shs: Option<secret::HashSuite> = None;
    let mut scs: Option<secret::CipherSuite> = None;
    let mut sqcs: Option<secret::QCipherSuite> = None;
    let mut sss: Option<secret::SignerSuite> = None;
    let mut sqss: Option<secret::QSignerSuite> = None;

    for candidate in &[secret::HashSuite::Sha3_512] {
        for item in hs {
            if item == candidate {
                shs = Some(*candidate);
            }
        }
    }

    for candidate in &[secret::CipherSuite::RSA2048] {
        for item in cs {
            if item == candidate {
                scs = Some(*candidate);
            }
        }
    }

    for candidate in &[secret::QCipherSuite::KYBER1024] {
        for item in qcs {
            if item == candidate {
                sqcs = Some(*candidate);
            }
        }
    }

    for candidate in &[secret::SignerSuite::ED25519] {
        for item in ss {
            if item == candidate {
                sss = Some(*candidate);
            }
        }
    }

    for candidate in &[secret::QSignerSuite::SPHINCSSHAKE256FSIMPLE] {
        for item in qss {
            if item == candidate {
                sqss = Some(*candidate);
            }
        }
    }

    if shs == None || scs == None || sqcs == None || sss == None || sqss == None {
        return Err(());
    }

    Ok((
        shs.unwrap(),
        scs.unwrap(),
        sqcs.unwrap(),
        sss.unwrap(),
        sqss.unwrap(),
    ))
}

#[derive(Serialize, Deserialize)]
enum HashSuiteOps {
    Selected(secret::HashSuite),
    List(Vec<secret::HashSuite>),
}

#[derive(Serialize, Deserialize)]
enum CipherSuiteOps {
    Selected(secret::CipherSuite),
    List(Vec<secret::CipherSuite>),
}

#[derive(Serialize, Deserialize)]
enum QCipherSuiteOps {
    Selected(secret::QCipherSuite),
    List(Vec<secret::QCipherSuite>),
}

#[derive(Serialize, Deserialize)]
enum SignerSuiteOps {
    Selected(secret::SignerSuite),
    List(Vec<secret::SignerSuite>),
}

#[derive(Serialize, Deserialize)]
enum QSignerSuiteOps {
    Selected(secret::QSignerSuite),
    List(Vec<secret::QSignerSuite>),
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
    hash_suits: HashSuiteOps,
    sign_suits: SignerSuiteOps,
    cipher_suits: CipherSuiteOps,
    q_sign_suits: QSignerSuiteOps,
    q_cipher_suits: QCipherSuiteOps,
}

impl Hello {
    fn new_request(id: [u8; 32]) -> Hello {
        Hello {
            id,
            version: VERSION.to_string(),
            sign_address: None,
            q_sign_address: None,
            cipher_address: None,
            q_cipher_address: None,
            hash_suits: HashSuiteOps::List(all::<secret::HashSuite>().collect()),
            sign_suits: SignerSuiteOps::List(all::<secret::SignerSuite>().collect()),
            cipher_suits: CipherSuiteOps::List(all::<secret::CipherSuite>().collect()),
            q_sign_suits: QSignerSuiteOps::List(all::<secret::QSignerSuite>().collect()),
            q_cipher_suits: QCipherSuiteOps::List(all::<secret::QCipherSuite>().collect()),
        }
    }

    fn new_response(
        id: [u8; 32],
        sign_address: String,
        q_sign_address: String,
        cipher_address: String,
        q_cipher_address: String,
        hash_suite: secret::HashSuite,
        signer_suit: secret::SignerSuite,
        cipher_suits: secret::CipherSuite,
        q_sign_suits: secret::QSignerSuite,
        q_cipher_suits: secret::QCipherSuite,
    ) -> Hello {
        Hello {
            id,
            sign_address: Some(sign_address),
            q_sign_address: Some(q_sign_address),
            cipher_address: Some(cipher_address),
            q_cipher_address: Some(q_cipher_address),
            version: VERSION.to_string(),
            hash_suits: HashSuiteOps::Selected(hash_suite),
            sign_suits: SignerSuiteOps::Selected(signer_suit),
            cipher_suits: CipherSuiteOps::Selected(cipher_suits),
            q_sign_suits: QSignerSuiteOps::Selected(q_sign_suits),
            q_cipher_suits: QCipherSuiteOps::Selected(q_cipher_suits),
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
        match &self.hash_suits {
            HashSuiteOps::List(set) => {
                for _ in set.iter() {
                    size += 1;
                }
            }
            HashSuiteOps::Selected(_) => {
                size += 1;
            }
        };
        match &self.sign_suits {
            SignerSuiteOps::List(set) => {
                for i in set.iter() {
                    size += 1;
                }
            }
            SignerSuiteOps::Selected(_) => {
                size += 1;
            }
        };
        match &self.cipher_suits {
            CipherSuiteOps::List(set) => {
                for _ in set.iter() {
                    size += 1;
                }
            }
            CipherSuiteOps::Selected(_) => {
                size += 1;
            }
        };
        match &self.q_sign_suits {
            QSignerSuiteOps::List(set) => {
                for _ in set.iter() {
                    size += 1;
                }
            }
            QSignerSuiteOps::Selected(_) => {
                size += 1;
            }
        };
        match &self.q_cipher_suits {
            QCipherSuiteOps::List(set) => {
                for _ in set.iter() {
                    size += 1;
                }
            }
            QCipherSuiteOps::Selected(_) => {
                size += 1;
            }
        };

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

        match &self.hash_suits {
            HashSuiteOps::List(set) => {
                for i in set.iter() {
                    buf.push(*i as u8);
                }
            }
            HashSuiteOps::Selected(selected) => buf.push(*selected as u8),
        };
        match &self.sign_suits {
            SignerSuiteOps::List(set) => {
                for i in set.iter() {
                    buf.push(*i as u8);
                }
            }
            SignerSuiteOps::Selected(selected) => buf.push(*selected as u8),
        };
        match &self.cipher_suits {
            CipherSuiteOps::List(set) => {
                for i in set.iter() {
                    buf.push(*i as u8);
                }
            }
            CipherSuiteOps::Selected(selected) => buf.push(*selected as u8),
        };
        match &self.q_sign_suits {
            QSignerSuiteOps::List(set) => {
                for i in set.iter() {
                    buf.push(*i as u8);
                }
            }
            QSignerSuiteOps::Selected(selected) => buf.push(*selected as u8),
        };
        match &self.q_cipher_suits {
            QCipherSuiteOps::List(set) => {
                for i in set.iter() {
                    buf.push(*i as u8);
                }
            }
            QCipherSuiteOps::Selected(selected) => buf.push(*selected as u8),
        };

        buf
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

/// State contains handshake state and agreed cryptography and post-quantum cryptography protocols.
/// The task of this entity is to create SecretKey that is in further use to encrypt data exchange between E2E clients.
///
pub struct State {
    id: Option<[u8; 32]>,
    position: Position,
    cipher_creator: Option<secret::CipherCreator>,
    handshake_data: Vec<u8>,
    shared_key: Option<Vec<u8>>,
}

impl State {
    /// Creates new Assignation entity with empty Cipher Suits.
    ///
    pub fn new() -> State {
        State {
            id: None,
            position: Position::Reset,
            cipher_creator: None,
            handshake_data: Vec::new(),
            shared_key: None,
        }
    }

    /// Resets selected hashers, signers and encapsulators, cleans the handshake data.
    /// This method allows to reset the entity before reusing it,
    /// but all cipher suits are still in the hashmaps ready to be used.
    ///
    pub fn reset(&mut self) {
        self.id = None;
        self.cipher_creator = None;
        self.handshake_data = Vec::new();
        self.position = Position::Reset;
    }

    /// Create hello with proposed protocols for the handshake.
    ///
    pub fn hello_propose(&mut self) -> Result<Hello, ErrorSecure> {
        if self.position != Position::Reset {
            return Err(ErrorSecure::StateNotReset);
        }

        let id_slice = random_hash();
        if id_slice.len() != 32 {
            return Err(ErrorSecure::UnexpectedFailure);
        }

        let mut id_arr: [u8; 32] = [0u8; 32];

        for i in 0..id_slice.len() {
            id_arr[i] = id_slice[i];
        }

        self.id = Some(id_arr);
        self.position = Position::Hello;

        let hello = Hello::new_request(id_arr);

        self.handshake_data.extend(hello.as_vector_bytes());

        Ok(hello)
    }

    pub fn hello_select(&mut self, hello: &Hello) -> Result<Hello, ErrorSecure> {
        if self.position != Position::Reset {
            return Err(ErrorSecure::StateNotReset);
        }

        let mut hs: secret::HashSuite = secret::HashSuite::Sha3_512;
        if let HashSuiteOps::Selected(hasher) = hello.hash_suits {
            hs = hasher;
        } else {
            return Err(ErrorSecure::WrongHelloStage);
        }

        let mut ss: secret::SignerSuite = secret::SignerSuite::ED25519;
        if let SignerSuiteOps::Selected(signer) = hello.sign_suits {
            ss = signer;
        } else {
            return Err(ErrorSecure::WrongHelloStage);
        }

        let mut qss: secret::QSignerSuite = secret::QSignerSuite::SPHINCSSHAKE256FSIMPLE;
        if let QSignerSuiteOps::Selected(signer) = hello.q_sign_suits {
            qss = signer;
        } else {
            return Err(ErrorSecure::WrongHelloStage);
        }

        let mut cs: secret::CipherSuite = secret::CipherSuite::RSA2048;
        if let CipherSuiteOps::Selected(cipher) = hello.cipher_suits {
            cs = cipher;
        } else {
            return Err(ErrorSecure::WrongHelloStage);
        }
        let mut qcs: secret::QCipherSuite = secret::QCipherSuite::KYBER1024;
        if let QCipherSuiteOps::Selected(cipher) = hello.q_cipher_suits {
            qcs = cipher;
        } else {
            return Err(ErrorSecure::WrongHelloStage);
        }

        self.cipher_creator = Some(secret::CipherCreator::with_params(hs, cs, ss, qcs, qss)?);
        let (s, qs, c, qc) = self.cipher_creator.as_ref().unwrap().addresses();

        let hello_response = Hello::new_response(hello.id, s, qs, c, qc, hs, ss, cs, qss, qcs);

        self.handshake_data.extend(hello.as_vector_bytes());
        self.handshake_data.extend(hello_response.as_vector_bytes());
        self.position = Position::Hello;
        self.id = Some(hello.id);

        Ok(hello_response)
    }

    pub fn cipher_generate(&mut self, hello: &Hello) -> Result<secret::Cipher, ErrorSecure> {
        if self.position != Position::Hello {
            return Err(ErrorSecure::StateNotHello);
        }
        self.handshake_data.extend(hello.as_vector_bytes());
        if let Some(ck) = &mut self.cipher_creator {
            let c_a = hello
                .cipher_address
                .clone()
                .ok_or(ErrorSecure::UnexpectedFailure)?;
            let qc_a = hello
                .q_cipher_address
                .clone()
                .ok_or(ErrorSecure::UnexpectedFailure)?;
            let (shared_key, cipher) = ck.pack_to_cipher(&self.handshake_data, c_a, qc_a)?;
            self.shared_key = Some(shared_key);
            return Ok(cipher);
        }
        return Err(ErrorSecure::NoCipherCreator);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fool_successful_handshake() {}
}
