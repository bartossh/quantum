/// Get a copy of Self as vector of bytes.
///
pub trait AsVectorBytes {
    fn as_vector_bytes(&self) -> Vec<u8>;
}

/// AddressReadValidator reads and validates entity address.
pub trait AddressReader {
    /// Returns public key as base58 encoded string.
    ///
    fn address(&self) -> String;
}

/// Errors describing EncapsulatorDecapsulator failures.
///
#[derive(Debug)]
pub enum ErrorSecure {
    InvalidPublicKey,
    InvalidSignature,
    InvalidCipher,
    NoCipherCreator,
    UnexpectedFailure,
    WrongHelloStage,
    InvalidHash,
    EntityAlreadyExists,
    SelectedHasherDoesNotExist,
    SelectedSignerDoesNotExist,
    SelectedEncapsulatorDoesNotExist,
    StateNotReset,
    StateNotHello,
    WrongIdPresented,
}

/// Signer signs the message returning DetachedSignature.
///
pub trait Signer {
    /// Signs message returning signature as vector of bytes.
    ///
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
}

/// Validator validates the massage against the DetachedSignature.
///
pub trait Verifier {
    /// Validate self signed message.
    ///
    fn validate_self(&self, msg: &[u8], sig: &[u8]) -> Result<(), ErrorSecure>;

    /// Validate message signed by other Signer.
    ///
    fn validate_other(&self, msg: &[u8], sig: &[u8], address: &str) -> Result<(), ErrorSecure>;
}

/// SignerVerifierAddressReader combines Signer, Verifier and AddressReader traits.
///
pub trait SignerVerifierAddressReader: Signer + Verifier + AddressReader {}

/// EncapsulatorDecapsulator generates shared key and encapsulates the shared key
/// and decapsulates shared key using post-quantum asymmetric key cryptography.
///
pub trait EncapsulatorDecapsulator {
    /// Encapsulated generated shared secret key as raw vector of bytes and the ciphertext.
    /// First entity in the Result success tuple is SecretKey and Second one is Ciphertext.
    /// # Examples
    ///
    fn encapsulate_shared_key(&self, address: String) -> Result<(Vec<u8>, Vec<u8>), ErrorSecure>;

    /// Decapsulates shared secret key from bytes array.
    /// Result success contains vector of bytes representing shared key.
    ///
    fn decapsulate_shared_key(&self, cipher: &[u8]) -> Result<Vec<u8>, ErrorSecure>;
}

/// EncapsulatorDecapsulatorAddressReader combines EncapsulatorDecapsulator and AddressReader traits.
///
pub trait EncapsulatorDecapsulatorAddressReader: EncapsulatorDecapsulator + AddressReader {}

/// EncryptorDecryptor encrypts and decrypts message using asymmetric key cryptography.
pub trait EncryptorDecryptor {
    /// Encrypts the message for given public address.
    ///
    fn encrypt(&self, address: String, msg: &[u8]) -> Result<Vec<u8>, ErrorSecure>;

    /// Decrypts message encoded for Self with Self public address.
    ///
    fn decrypt(&self, msg: &[u8]) -> Result<Vec<u8>, ErrorSecure>;
}

/// EncryptorDecryptor combines EncryptorDecryptor and AddressReader traits.
///
pub trait EncryptorDecryptorAddressReader: EncryptorDecryptor + AddressReader {}

/// Hasher hashes the given slice of bytes.
///
pub trait Hasher {
    /// Hashes slice and returns digested vector.
    ///
    fn hash(&mut self, slice: &[u8]) -> Vec<u8>;

    /// Resets hasher.
    ///
    fn reset(&mut self);

    /// Hashes given slice and resets the hasher, returns digested vector.
    ///
    fn hash_reset(&mut self, slice: &[u8]) -> Vec<u8>;
}
