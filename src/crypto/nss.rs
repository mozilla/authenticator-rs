use super::{ECDHSecret, Key, PublicKey, SignatureAlgorithm};
use serde_bytes::ByteBuf;

/// Errors that can be returned from COSE functions.
#[derive(Debug, PartialEq)]
pub enum BackendError {
    NSSError,
}

pub type Result<T> = std::result::Result<T, BackendError>;

/* From CTAP2.1 spec:

initialize()

    This is run by the platform when starting a series of transactions with a specific authenticator.
encapsulate(peerCoseKey) → (coseKey, sharedSecret) | error

    Generates an encapsulation for the authenticator’s public key and returns the message to transmit and the shared secret.
encrypt(key, demPlaintext) → ciphertext

    Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext. The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
decrypt(key, ciphertext) → plaintext | error

    Decrypts a ciphertext and returns the plaintext.
authenticate(key, message) → signature

    Computes a MAC of the given message.
*/

pub(crate) fn parse_key(curve: SignatureAlgorithm, x: &[u8], y: &[u8]) -> Result<PublicKey> {
    compile_error!(
        "NSS-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}

// TODO(MS): Maybe remove ByteBuf and return Vec<u8>'s instead for a cleaner interface
pub(crate) fn serialize_key<T: Key>(key: &T) -> Result<(ByteBuf, ByteBuf)> {
    compile_error!(
        "NSS-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}

/// This is run by the platform when starting a series of transactions with a specific authenticator.
pub(crate) fn initialize() {
    compile_error!(
        "NSS-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}

/// Generates an encapsulation for the authenticator’s public key and returns the message
/// to transmit and the shared secret.
pub(crate) fn encapsulate<T: Key>(key: &T) -> Result<ECDHSecret> {
    compile_error!(
        "NSS-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}

/// Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext.
/// The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
pub(crate) fn encrypt<T: Key>(
    key: &T,
    plain_text: &[u8], /*PlainText*/
) -> Result<Vec<u8> /*CypherText*/> {
    compile_error!(
        "NSS-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}

/// Decrypts a ciphertext and returns the plaintext.
pub(crate) fn decrypt<T: Key>(
    key: &T,
    cypher_text: &[u8], /*CypherText*/
) -> Result<Vec<u8> /*PlainText*/> {
    compile_error!(
        "NSS-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}

/// Computes a MAC of the given message.
pub(crate) fn authenticate(token: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    compile_error!(
        "NSS-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}
