/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::ring::rand::SecureRandom;
use crate::ring::signature::KeyPair;
use crate::Result;

pub trait CryptoProvider {
    fn new_key(&self) -> Result<Box<dyn Key>>;
    fn random_bytes(&self, destination: &mut [u8]) -> Result<()>;
}

pub trait Key {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn public(&self) -> Vec<u8>;
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
