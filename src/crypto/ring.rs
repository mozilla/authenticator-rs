use super::{ECDHSecret, Key, PublicKey, SignatureAlgorithm};
use ring::agreement::{Algorithm, ECDH_P256, ECDH_P384};
use ring::rand::SecureRandom;
use ring::signature::KeyPair;

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
        SignatureAlgorithm::PS256 => &ECDH_P256,
        SignatureAlgorithm::PS384 => &ECDH_P384,
        // SignatureAlgorithm::X25519 => ECDH_X25519,
        _ => unimplemented!(),
    }
}

#[derive(Debug, PartialEq)]
pub enum BackendError {
    RingError,
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
    let rng = rand::SystemRandom::new();
    let peer_public_key_alg = to_ring_curve(key.curve());
    let private_key = EphemeralPrivateKey::generate(peer_public_key_alg, &rng).map_err(|_| ())?;
    let my_public_key = private_key.compute_public_key().map_err(|_| ())?;
    let my_public_key = PublicKey {
        curve: key.curve(),
        bytes: Vec::from(my_public_key.as_ref()),
    };
    let peer_public_key = untrusted::Input::from(&key.key());

    let shared_secret = agreement::agree_ephemeral(
        private_key,
        peer_public_key_alg,
        peer_public_key,
        (),
        |key_material| {
            // TODO(baloo): this is too specific to ctap2, need to move that
            //              somewhere else
            let mut hasher = Sha256::new();
            hasher.input(key_material);
            Ok(Vec::from(hasher.result().as_slice()))
        },
    )?;

    Ok(ECDHSecret {
        curve: key.curve(),
        remote: key.key().to_vec(),
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
    compile_error!(
        "Ring-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}

/// Decrypts a ciphertext and returns the plaintext.
pub(crate) fn decrypt<T: Key>(
    key: &T,
    cypher_text: &[u8], /*CypherText*/
) -> Result<Vec<u8> /*PlainText*/> {
    compile_error!(
        "Ring-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}

/// Computes a MAC of the given message.
pub(crate) fn authenticate(token: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    compile_error!(
        "Ring-backend is not yet implemented. Compile with `--features crypto_openssl` for now."
    )
}
