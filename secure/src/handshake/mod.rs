mod secret;
use crate::globals::{AsVectorBytes, ErrorSecure};
use crate::randomizer::generate_random_hash;
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
    ErrorSecure,
> {
    let mut shs: Option<secret::HashSuite> = None;
    let mut scs: Option<secret::CipherSuite> = None;
    let mut sqcs: Option<secret::QCipherSuite> = None;
    let mut sss: Option<secret::SignerSuite> = None;
    let mut sqss: Option<secret::QSignerSuite> = None;

    'hash_loop: for candidate in &[secret::HashSuite::Sha3_512] {
        for item in hs {
            if item == candidate {
                shs = Some(*candidate);
                break 'hash_loop;
            }
        }
    }

    'cipher_loop: for candidate in &[secret::CipherSuite::RSA2048] {
        for item in cs {
            if item == candidate {
                scs = Some(*candidate);
                break 'cipher_loop;
            }
        }
    }

    'qcipher_loop: for candidate in &[secret::QCipherSuite::KYBER1024] {
        for item in qcs {
            if item == candidate {
                sqcs = Some(*candidate);
                break 'qcipher_loop;
            }
        }
    }

    'signer_loop: for candidate in &[secret::SignerSuite::ED25519] {
        for item in ss {
            if item == candidate {
                sss = Some(*candidate);
                break 'signer_loop;
            }
        }
    }

    'qsigner_loop: for candidate in &[secret::QSignerSuite::SPHINCSSHAKE256FSIMPLE] {
        for item in qss {
            if item == candidate {
                sqss = Some(*candidate);
                break 'qsigner_loop;
            }
        }
    }

    if shs == None || scs == None || sqcs == None || sss == None || sqss == None {
        return Err(ErrorSecure::WrongHelloSuitsStage);
    }

    Ok((
        shs.unwrap(),
        scs.unwrap(),
        sqcs.unwrap(),
        sss.unwrap(),
        sqss.unwrap(),
    ))
}

#[derive(Debug, Serialize, Deserialize)]
enum HashSuiteOps {
    Selected(secret::HashSuite),
    List(Vec<secret::HashSuite>),
}

impl HashSuiteOps {
    fn into_list(&self) -> Result<&Vec<secret::HashSuite>, ErrorSecure> {
        match &self {
            HashSuiteOps::List(list) => Ok(list),
            _ => Err(ErrorSecure::WrongHelloSuitsStage),
        }
    }

    fn into_selected(&self) -> Result<&secret::HashSuite, ErrorSecure> {
        match &self {
            HashSuiteOps::Selected(s) => Ok(s),
            _ => Err(ErrorSecure::WrongHelloSuitsStage),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum CipherSuiteOps {
    Selected(secret::CipherSuite),
    List(Vec<secret::CipherSuite>),
}

impl CipherSuiteOps {
    fn into_list(&self) -> Result<&Vec<secret::CipherSuite>, ErrorSecure> {
        match &self {
            CipherSuiteOps::List(list) => Ok(list),
            _ => Err(ErrorSecure::WrongHelloSuitsStage),
        }
    }

    fn into_selected(&self) -> Result<&secret::CipherSuite, ErrorSecure> {
        match &self {
            CipherSuiteOps::Selected(s) => Ok(s),
            _ => Err(ErrorSecure::WrongHelloSuitsStage),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum QCipherSuiteOps {
    Selected(secret::QCipherSuite),
    List(Vec<secret::QCipherSuite>),
}

impl QCipherSuiteOps {
    fn into_list(&self) -> Result<&Vec<secret::QCipherSuite>, ErrorSecure> {
        match &self {
            QCipherSuiteOps::List(list) => Ok(list),
            _ => Err(ErrorSecure::WrongHelloSuitsStage),
        }
    }

    fn into_selected(&self) -> Result<&secret::QCipherSuite, ErrorSecure> {
        match &self {
            QCipherSuiteOps::Selected(s) => Ok(s),
            _ => Err(ErrorSecure::WrongHelloSuitsStage),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum SignerSuiteOps {
    Selected(secret::SignerSuite),
    List(Vec<secret::SignerSuite>),
}

impl SignerSuiteOps {
    fn into_list(&self) -> Result<&Vec<secret::SignerSuite>, ErrorSecure> {
        match &self {
            SignerSuiteOps::List(list) => Ok(list),
            _ => Err(ErrorSecure::WrongHelloSuitsStage),
        }
    }

    fn into_selected(&self) -> Result<&secret::SignerSuite, ErrorSecure> {
        match &self {
            SignerSuiteOps::Selected(s) => Ok(s),
            _ => Err(ErrorSecure::WrongHelloSuitsStage),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum QSignerSuiteOps {
    Selected(secret::QSignerSuite),
    List(Vec<secret::QSignerSuite>),
}

impl QSignerSuiteOps {
    fn into_list(&self) -> Result<&Vec<secret::QSignerSuite>, ErrorSecure> {
        match &self {
            QSignerSuiteOps::List(list) => Ok(list),
            _ => Err(ErrorSecure::WrongHelloSuitsStage),
        }
    }

    fn into_selected(&self) -> Result<&secret::QSignerSuite, ErrorSecure> {
        match &self {
            QSignerSuiteOps::Selected(s) => Ok(s),
            _ => Err(ErrorSecure::WrongHelloSuitsStage),
        }
    }
}

/// Hello message allows to agree cipher suits that will be used to create E2E ephemeral key
/// exchange between E2E clients with selected cipher suit.
///  
#[derive(Debug, Serialize, Deserialize)]
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
    fn new_request(id: [u8; 32]) -> Self {
        Self {
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
    ) -> Self {
        Self {
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
                for _ in set.iter() {
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
    pub fn new() -> Self {
        Self {
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

        let id_slice = generate_random_hash();
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

        let (hs, cs, qcs, ss, qss) = get_precedence(
            hello.hash_suits.into_list()?,
            hello.cipher_suits.into_list()?,
            hello.q_cipher_suits.into_list()?,
            hello.sign_suits.into_list()?,
            hello.q_sign_suits.into_list()?,
        )?;

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

        self.cipher_creator = Some(secret::CipherCreator::with_params(
            *hello.hash_suits.into_selected()?,
            *hello.cipher_suits.into_selected()?,
            *hello.sign_suits.into_selected()?,
            *hello.q_cipher_suits.into_selected()?,
            *hello.q_sign_suits.into_selected()?,
        )?);
        self.handshake_data.extend(hello.as_vector_bytes());
        let c_a = hello
            .cipher_address
            .clone()
            .ok_or(ErrorSecure::UnexpectedFailure)?;
        let qc_a = hello
            .q_cipher_address
            .clone()
            .ok_or(ErrorSecure::UnexpectedFailure)?;
        let (shared_key, cipher) = self.cipher_creator.as_mut().unwrap().pack_to_cipher(
            &self.handshake_data,
            c_a,
            qc_a,
        )?;
        self.shared_key = Some(shared_key);
        self.position = Position::SharedKey;
        return Ok(cipher);
    }

    pub fn cipher_decode_sharedkey(&mut self, cipher: &secret::Cipher) -> Result<(), ErrorSecure> {
        if self.position != Position::Hello {
            return Err(ErrorSecure::StateNotHello);
        }
        if let Some(ck) = &mut self.cipher_creator {
            self.shared_key = Some(ck.unpack_from_cipher(&cipher, &self.handshake_data)?);
            return Ok(());
        }

        Err(ErrorSecure::NoCipherCreator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_should_perform_full_successful_handshake() {
        let handshakes_num: usize = 5;
        let mut alice = State::new();
        let mut bob = State::new();

        for _ in 0..handshakes_num {
            let h = alice.hello_propose();
            if h.is_err() {
                assert!(false);
            }

            let h = bob.hello_select(&h.unwrap());
            if h.is_err() {
                dbg!(&h);
                assert!(false);
            }

            let c = alice.cipher_generate(&h.unwrap());
            if c.is_err() {
                dbg!(&c);
                assert!(false);
            }

            let r = bob.cipher_decode_sharedkey(&c.unwrap());
            if r.is_err() {
                dbg!(&r);
                assert!(false);
            }

            assert_eq!(
                &alice.shared_key.clone().unwrap(),
                &bob.shared_key.clone().unwrap()
            );

            alice.reset();
            bob.reset();
        }
    }

    #[test]
    fn it_should_not_allow_to_perform_full_successful_handshake_with_mitm_attack_on_hello_select() {
        let handshakes_num: usize = 5;
        let mut alice = State::new();
        let mut bob = State::new();
        let mut clint = State::new();

        for _ in 0..handshakes_num {
            let h = alice.hello_propose();
            if h.is_err() {
                assert!(false);
            }

            let bh = bob.hello_select(&h.as_ref().unwrap());
            if bh.is_err() {
                dbg!(&bh);
                assert!(false);
            }

            let ch = clint.hello_select(&h.unwrap());
            if ch.is_err() {
                dbg!(&ch);
                assert!(false);
            }

            let c = alice.cipher_generate(&ch.unwrap());
            if c.is_err() {
                dbg!(&c);
                assert!(false);
            }

            let r = bob.cipher_decode_sharedkey(&c.unwrap());
            match r {
                Ok(o) => {
                    dbg!(&o);
                    assert!(false);
                }
                Err(e) => {
                    if e != ErrorSecure::InvalidHash {
                        dbg!(&e);
                        assert!(false);
                    }
                }
            }
            alice.reset();
            bob.reset();
            clint.reset();
        }
    }

    #[test]
    fn it_should_not_allow_to_perform_full_successful_handshake_with_mitm_attack_on_cipher_generate(
    ) {
        let handshakes_num: usize = 5;
        let mut alice = State::new();
        let mut bob = State::new();
        let mut clint = State::new();

        for _ in 0..handshakes_num {
            let h = alice.hello_propose();
            if h.is_err() {
                assert!(false);
            }

            let bh = bob.hello_select(&h.as_ref().unwrap());
            if bh.is_err() {
                dbg!(&bh);
                assert!(false);
            }

            let ch = clint.hello_select(&h.as_ref().unwrap());
            if ch.is_err() {
                dbg!(&ch);
                assert!(false);
            }

            let ca = alice.cipher_generate(&bh.as_ref().unwrap());
            if ca.is_err() {
                dbg!(&ca);
                assert!(false);
            }

            let cc = clint.cipher_generate(&bh.unwrap());
            if cc.is_err() {
                dbg!(&cc);
                assert!(false);
            }

            let r = bob.cipher_decode_sharedkey(&cc.unwrap());
            match r {
                Ok(o) => {
                    dbg!(&o);
                    assert!(false);
                }
                Err(e) => {
                    if e != ErrorSecure::InvalidHash {
                        dbg!(&e);
                        assert!(false);
                    }
                }
            }
            alice.reset();
            bob.reset();
            clint.reset();
        }
    }

    #[test]
    fn it_should_not_allow_to_perform_full_successful_handshake_with_mitm_attack_on_hello_propose()
    {
        let handshakes_num: usize = 5;
        let mut alice = State::new();
        let mut bob = State::new();
        let mut clint = State::new();

        for _ in 0..handshakes_num {
            let h = alice.hello_propose();
            if h.is_err() {
                assert!(false);
            }

            let ch = clint.hello_propose();
            if ch.is_err() {
                assert!(false);
            }

            let bh = bob.hello_select(&ch.as_ref().unwrap());
            if bh.is_err() {
                dbg!(&bh);
                assert!(false);
            }

            let ca = alice.cipher_generate(&bh.as_ref().unwrap());
            if ca.is_err() {
                dbg!(&ca);
                assert!(false);
            }

            let r = bob.cipher_decode_sharedkey(&ca.unwrap());
            match r {
                Ok(o) => {
                    dbg!(&o);
                    assert!(false);
                }
                Err(e) => {
                    if e != ErrorSecure::InvalidHash {
                        dbg!(&e);
                        assert!(false);
                    }
                }
            }
            alice.reset();
            bob.reset();
            clint.reset();
        }
    }
}
