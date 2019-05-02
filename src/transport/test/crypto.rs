use ring::{
    error::{KeyRejected, Unspecified},
    rand,
    signature::{self, EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};

use cose::EllipticCurve;
pub use cose::PublicKey;

#[derive(Debug)]
pub enum Error {
    Generation(Unspecified),
    Invalid(KeyRejected),
}

#[derive(Debug)]
pub struct PrivateKey(EcdsaKeyPair);

impl PrivateKey {
    pub fn generate() -> Result<Self, Error> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes =
            signature::EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .map_err(Error::Generation)?;
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            untrusted::Input::from(pkcs8_bytes.as_ref()),
        )
        .map_err(Error::Invalid)?;
        Ok(PrivateKey(key_pair))
    }

    pub fn public_key(&self) -> PublicKey {
        let pub_key = self.0.public_key();
        PublicKey::new(EllipticCurve::P256, Vec::from(pub_key.as_ref()))
    }
}
