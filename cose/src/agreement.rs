use std::fmt;

use ring::agreement::{self, EphemeralPrivateKey};
use ring::rand;
use sha2::{Digest, Sha256};

use crate::{EllipticCurve, PublicKey};

pub trait Agreement {
    fn complete_handshake(&self) -> Result<ECDHSecret, ()>;
}

impl Agreement for PublicKey {
    fn complete_handshake(&self) -> Result<ECDHSecret, ()> {
        let rng = rand::SystemRandom::new();
        let peer_public_key_alg = self.curve.to_ring_curve();
        let private_key =
            EphemeralPrivateKey::generate(peer_public_key_alg, &rng).map_err(|_| ())?;
        let my_public_key = private_key.compute_public_key().map_err(|_| ())?;
        let my_public_key = PublicKey {
            curve: self.curve,
            bytes: Vec::from(my_public_key.as_ref()),
        };
        let peer_public_key = untrusted::Input::from(&self.bytes[..]);

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
            curve: self.curve,
            remote: self.clone(),
            my: my_public_key,
            shared_secret,
        })
    }
}

#[derive(Clone)]
pub struct ECDHSecret {
    curve: EllipticCurve,
    remote: PublicKey,
    my: PublicKey,
    shared_secret: Vec<u8>,
}

impl ECDHSecret {
    pub fn my_public_key(&self) -> &PublicKey {
        &self.my
    }

    pub fn shared_secret(&self) -> &[u8] {
        self.shared_secret.as_ref()
    }
}

impl fmt::Debug for ECDHSecret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ECDHSecret(remote: {:?}, my: {:?})",
            self.remote,
            self.my_public_key()
        )
    }
}

#[cfg(test)]
mod test {
    use super::{EllipticCurve, PublicKey};

    #[test]
    fn test_format_public_numbers() {
        let key = PublicKey {
            curve: EllipticCurve::P256,
            bytes: vec![
                0x04, 0xfc, 0x9e, 0xd3, 0x6f, 0x7c, 0x1a, 0xa9, 0x15, 0xce, 0x3e, 0xa1, 0x77, 0xf0,
                0x75, 0x67, 0xf0, 0x7f, 0x16, 0xf9, 0x47, 0x9d, 0x95, 0xad, 0x8e, 0xd4, 0x97, 0x1d,
                0x33, 0x05, 0xe3, 0x1a, 0x80, 0x50, 0xb7, 0x33, 0xaf, 0x8c, 0x0b, 0x0e, 0xe1, 0xda,
                0x8d, 0xe0, 0xac, 0xf9, 0xd8, 0xe1, 0x32, 0x82, 0xf0, 0x63, 0xb7, 0xb3, 0x0d, 0x73,
                0xd4, 0xd3, 0x2c, 0x9a, 0xad, 0x6d, 0xfa, 0x8b, 0x27,
            ],
        };

        let (x, y) = key.affine_coordinates().unwrap();

        assert_eq!(
            &x[..],
            &[
                0xfc, 0x9e, 0xd3, 0x6f, 0x7c, 0x1a, 0xa9, 0x15, 0xce, 0x3e, 0xa1, 0x77, 0xf0, 0x75,
                0x67, 0xf0, 0x7f, 0x16, 0xf9, 0x47, 0x9d, 0x95, 0xad, 0x8e, 0xd4, 0x97, 0x1d, 0x33,
                0x05, 0xe3, 0x1a, 0x80
            ]
        );
        assert_eq!(
            &y[..],
            &[
                0x50, 0xb7, 0x33, 0xaf, 0x8c, 0x0b, 0x0e, 0xe1, 0xda, 0x8d, 0xe0, 0xac, 0xf9, 0xd8,
                0xe1, 0x32, 0x82, 0xf0, 0x63, 0xb7, 0xb3, 0x0d, 0x73, 0xd4, 0xd3, 0x2c, 0x9a, 0xad,
                0x6d, 0xfa, 0x8b, 0x27
            ]
        );
    }
}
