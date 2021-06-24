use super::{CryptoProvider, Key};
use crate::{errors::AuthenticatorError, Result};
use ring::rand::SecureRandom;
use ring::signature::KeyPair;

impl From<ring::error::Unspecified> for AuthenticatorError {
    fn from(_: ring::error::Unspecified) -> Self {
        AuthenticatorError::CryptoError
    }
}

impl From<ring::error::KeyRejected> for AuthenticatorError {
    fn from(_: ring::error::KeyRejected) -> Self {
        AuthenticatorError::CryptoError
    }
}

pub struct RingCryptoProvider {
    rng: ring::rand::SystemRandom,
}

impl RingCryptoProvider {
    pub fn new() -> RingCryptoProvider {
        RingCryptoProvider {
            rng: ring::rand::SystemRandom::new(),
        }
    }
}

impl CryptoProvider for RingCryptoProvider {
    fn new_key(&self) -> Result<Box<dyn Key>> {
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &self.rng,
        )?;
        let handle = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
        )?;
        Ok(Box::new(RingKey {
            handle,
            rng: self.rng.clone(),
        }))
    }

    fn random_bytes(&self, destination: &mut [u8]) -> Result<()> {
        self.rng.fill(destination)?;
        Ok(())
    }
}

pub struct RingKey {
    handle: ring::signature::EcdsaKeyPair,
    rng: ring::rand::SystemRandom,
}

impl Key for RingKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signature = self.handle.sign(&self.rng, data)?;
        Ok(signature.as_ref().to_vec())
    }

    fn public(&self) -> Vec<u8> {
        self.handle.public_key().as_ref().to_vec()
    }
}
