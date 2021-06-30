use super::{ECDHSecret, Key, PublicKey, SignatureAlgorithm};
use ring::agreement::{
    agree_ephemeral, Algorithm, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256, ECDH_P384,
};
use ring::digest;
use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::KeyPair;
use serde_bytes::ByteBuf;

/*
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

fn to_ring_curve(curve: SignatureAlgorithm) -> &'static Algorithm {
    match curve {
        SignatureAlgorithm::ES256 => &ECDH_P256,
        SignatureAlgorithm::ES384 => &ECDH_P384,
        // SignatureAlgorithm::X25519 => ECDH_X25519,
        _ => unimplemented!(),
    }
}

#[derive(Debug, PartialEq)]
pub enum BackendError {
    AgreementError,
    UnspecifiedRingError,
    KeyRejected,
}

impl From<ring::error::Unspecified> for BackendError {
    fn from(e: ring::error::Unspecified) -> Self {
        BackendError::UnspecifiedRingError
    }
}

impl From<ring::error::KeyRejected> for BackendError {
    fn from(e: ring::error::KeyRejected) -> Self {
        BackendError::KeyRejected
    }
}

pub type Result<T> = std::result::Result<T, BackendError>;

pub(crate) fn parse_key(curve: SignatureAlgorithm, x: &[u8], y: &[u8]) -> Result<PublicKey> {
    compile_error!(
        "Ring-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}

// TODO(MS): Maybe remove ByteBuf and return Vec<u8>'s instead for a cleaner interface
pub(crate) fn serialize_key<T: Key>(key: &T) -> Result<(ByteBuf, ByteBuf)> {
    compile_error!(
        "Ring-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}

/// This is run by the platform when starting a series of transactions with a specific authenticator.
pub(crate) fn initialize() {
    compile_error!(
        "Ring-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}

/// Generates an encapsulation for the authenticator’s public key and returns the message
/// to transmit and the shared secret.
pub(crate) fn encapsulate<T: Key>(key: &T) -> Result<ECDHSecret> {
    let rng = SystemRandom::new();
    let peer_public_key_alg = to_ring_curve(key.curve());
    let private_key = EphemeralPrivateKey::generate(peer_public_key_alg, &rng)?;
    let my_public_key = private_key.compute_public_key()?;
    let my_public_key = PublicKey {
        curve: key.curve(),
        bytes: Vec::from(my_public_key.as_ref()),
    };
    let peer_public_key = UnparsedPublicKey::new(peer_public_key_alg, &key.key());

    let shared_secret = agree_ephemeral(private_key, &peer_public_key, (), |key_material| {
        let digest = digest::digest(&digest::SHA256, key_material);
        Ok(Vec::from(digest.as_ref()))
    })
    .map_err(|_| BackendError::AgreementError)?;

    Ok(ECDHSecret {
        curve: key.curve(),
        remote: PublicKey {
            curve: key.curve(),
            bytes: key.key().to_vec(),
        },
        my: my_public_key,
        shared_secret,
    })
}

/// Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext.
/// The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
pub(crate) fn encrypt<T: Key>(
    key: &T,
    plain_text: &[u8], /*PlainText*/
) -> Result<Vec<u8> /*CypherText*/> {
    // Ring doesn't support AES-CBC yet
    compile_error!(
        "Ring-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}

/// Decrypts a ciphertext and returns the plaintext.
pub(crate) fn decrypt<T: Key>(
    key: &T,
    cypher_text: &[u8], /*CypherText*/
) -> Result<Vec<u8> /*PlainText*/> {
    // Ring doesn't support AES-CBC yet
    compile_error!(
        "Ring-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}

/// Computes a MAC of the given message.
pub(crate) fn authenticate(token: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let s_key = hmac::Key::new(hmac::HMAC_SHA256, token);
    let tag = hmac::sign(&s_key, input);
    Ok(tag.as_ref().to_vec())
}
