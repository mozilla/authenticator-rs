use super::{ECDHSecret, Key, PublicKey, SignatureAlgorithm};
use nss::aes::{common_crypt, Operation};
use nss_sys;
use rc_crypto::agreement::{
    Algorithm, Curve, EcKey, Ephemeral, KeyPair, PrivateKey, UnparsedPublicKey, ECDH_P256,
    ECDH_P384,
};
use rc_crypto::digest::digest;
use rc_crypto::hmac::{sign, SigningKey};
use rc_crypto::pbkdf2::HashAlgorithm;
use serde_bytes::ByteBuf;
use std::convert::TryFrom;
use std::os::raw::{c_uchar, c_uint};

/// Errors that can be returned from COSE functions.
#[derive(Debug)]
pub enum BackendError {
    NSSError(rc_crypto::Error),
    TryFromError,
}

impl From<rc_crypto::Error> for BackendError {
    fn from(e: rc_crypto::Error) -> Self {
        BackendError::NSSError(e)
    }
}

pub type Result<T> = std::result::Result<T, BackendError>;

fn to_nss_alg(curve: SignatureAlgorithm) -> &'static Algorithm {
    match curve {
        SignatureAlgorithm::ES256 => &ECDH_P256, // TODO(MS): Is this correct?
        SignatureAlgorithm::PS256 => &ECDH_P256,
        SignatureAlgorithm::ES384 => &ECDH_P384,
        // SignatureAlgorithm::X25519 => "x25519",
        _ => unimplemented!(),
    }
}

fn to_nss_curve(curve: SignatureAlgorithm) -> Curve {
    match curve {
        SignatureAlgorithm::ES256 => Curve::P256, // TODO(MS): Is this correct?
        SignatureAlgorithm::PS256 => Curve::P256,
        SignatureAlgorithm::ES384 => Curve::P384,
        // SignatureAlgorithm::X25519 => "x25519",
        _ => unimplemented!(),
    }
}

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
    let nss_name = to_nss_curve(curve);
    // Note:: NSSPublicKey does not provide the from_coordinates-function, so we have to go via EcKey
    //        and fake a private key.
    let key =
        EcKey::from_coordinates(nss_name, &[], x, y).map_err(|e| rc_crypto::Error::from(e))?;

    Ok(PublicKey {
        curve,
        bytes: key.public_key().to_vec(),
    })
}

// TODO(MS): Maybe remove ByteBuf and return Vec<u8>'s instead for a cleaner interface
pub(crate) fn serialize_key<T: Key>(key: &T) -> Result<(ByteBuf, ByteBuf)> {
    // TODO(MS): I actually have NO idea how to do this with NSS
    let length = key.key()[1..].len() / 2;
    let chunks: Vec<_> = key.key()[1..].chunks_exact(length).collect();
    Ok((
        ByteBuf::from(chunks[0].to_vec()),
        ByteBuf::from(chunks[1].to_vec()),
    ))
}

/// This is run by the platform when starting a series of transactions with a specific authenticator.
// pub(crate) fn initialize() {
//     unimplemented!()
// }

/// Generates an encapsulation for the authenticator’s public key and returns the message
/// to transmit and the shared secret.
pub(crate) fn encapsulate<T: Key>(key: &T) -> Result<ECDHSecret> {
    let alg = to_nss_alg(key.curve());
    let keypair: KeyPair<Ephemeral> = KeyPair::generate(alg)?;
    let (private_key, public_key) = keypair.split();
    encapsulate_helper(key, alg, &public_key.to_bytes()?, private_key)
}

fn encapsulate_helper<T: Key>(
    key: &T,
    alg: &'static Algorithm,
    public_key: &[u8],
    private_key: PrivateKey<Ephemeral>,
) -> Result<ECDHSecret> {
    let my_public_key = PublicKey {
        curve: key.curve(),
        bytes: public_key.to_vec(),
    };

    let peer_public_key = UnparsedPublicKey::new(alg, &key.key());

    let shared_secret = private_key.agree(&peer_public_key)?;
    let digest = shared_secret.derive(|input| digest(&HashAlgorithm::SHA256, input))?;

    Ok(ECDHSecret {
        curve: key.curve(),
        remote: PublicKey {
            curve: key.curve(),
            bytes: key.key().to_vec(),
        },
        my: my_public_key,
        shared_secret: digest.as_ref().to_vec(),
    })
}

#[cfg(test)]
pub(crate) fn test_encapsulate<T: Key>(
    key: &T,
    my_pub_key: &[u8],
    my_priv_key: &[u8],
) -> Result<ECDHSecret> {
    let curve = to_nss_curve(key.curve());
    let ec_key = EcKey::new(curve, my_priv_key, my_pub_key);
    let private_key = PrivateKey::import(&ec_key)?;
    let alg = to_nss_alg(key.curve());
    encapsulate_helper(
        key,
        alg,
        my_pub_key,
        private_key._tests_only_dangerously_convert_to_ephemeral(),
    )
}

/// Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext.
/// The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
pub(crate) fn encrypt<T: Key>(
    key: &T,
    plain_text: &[u8], /*PlainText*/
) -> Result<Vec<u8> /*CypherText*/> {
    crypt_helper(key, plain_text, Operation::Encrypt)
}

/// Decrypts a ciphertext and returns the plaintext.
pub(crate) fn decrypt<T: Key>(
    key: &T,
    cypher_text: &[u8], /*CypherText*/
) -> Result<Vec<u8> /*PlainText*/> {
    crypt_helper(key, cypher_text, Operation::Decrypt)
}

fn crypt_helper<T: Key>(key: &T, input: &[u8], operation: Operation) -> Result<Vec<u8>> {
    // Spec says explicitly IV=0
    let iv = [0u8; 16];

    // TODO(MS): aes_cbc_encrypt does padding, which we don't want. So we have to use common_encrypt
    // let plain_text = aes_cbc_crypt(key.key(), &iv, cypher_text, Operation::Decrypt)
    //     .map_err(|e| rc_crypto::Error::from(e))?;
    let mut params = nss_sys::SECItem {
        type_: nss_sys::SECItemType::siBuffer as u32,
        data: iv.as_ptr() as *mut c_uchar,
        len: c_uint::try_from(iv.len()).map_err(|_| BackendError::TryFromError)?,
    };
    let ckm_aes_ecb: u64 = 0x00001081; // copied from nss/lib/util/pkcs11t.h

    let output = common_crypt(
        ckm_aes_ecb.into(),
        key.key(),
        input,
        usize::try_from(nss_sys::AES_BLOCK_SIZE).map_err(|_| BackendError::TryFromError)?, // CBC mode might pad the result.
        &mut params,
        operation,
    )
    .map_err(|e| rc_crypto::Error::from(e))?;
    Ok(output)
}

/// Computes a MAC of the given message.
pub(crate) fn authenticate(token: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let key = SigningKey::new(&HashAlgorithm::SHA256, token);
    let hmac = sign(&key, input)?;
    Ok(hmac.as_ref().to_vec())
}
