use std::error::Error as StdErrorT;
use std::fmt;

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use ring::agreement::{self, Algorithm, EphemeralPrivateKey, ECDH_P256, ECDH_P384};
use ring::rand;
use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde::ser::{Error as SerdeSerError, Serialize, SerializeMap, Serializer};
use serde_bytes::ByteBuf;
use serde_cbor::Value;
use sha2::{Digest, Sha256};

const KEY_TYPE: u8 = 1;
const KEY_TYPE_EC2: u8 = 2;

#[derive(Debug)]
pub enum Error {
    UnsupportedCurve(u64),
    Openssl(ErrorStack),
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Error {
        Error::Openssl(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnsupportedCurve(v) => write!(f, "ECDHError: unsupported curve {}", v),
            Error::Openssl(ref e) => write!(f, "ECDHError: openssl: {}", e),
        }
    }
}

impl StdErrorT for Error {
    fn description(&self) -> &str {
        match *self {
            Error::UnsupportedCurve(_) => "ECDHError: unsupported curve",
            Error::Openssl(_) => "ECDHError: openssl error",
        }
    }
}

// https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
enum EllipticCurve {
    P256 = 1,
    P384 = 2,
    // TODO(baloo): looks unsupported by openssl, have to check
    //X25519 = 4,
}

impl EllipticCurve {
    pub fn from_u64(value: u64) -> Result<EllipticCurve, Error> {
        match value {
            1 => Ok(EllipticCurve::P256),
            2 => Ok(EllipticCurve::P384),
            //4 => Ok(EllipticCurve::X25519),
            e => Err(Error::UnsupportedCurve(e)),
        }
    }

    fn to_openssl_name(self) -> Nid {
        match self {
            EllipticCurve::P256 => Nid::X9_62_PRIME256V1,
            EllipticCurve::P384 => Nid::SECP384R1,
            // EllipticCurve::X25519 => "x25519",
        }
    }

    fn to_ring_curve(self) -> &'static Algorithm {
        match self {
            EllipticCurve::P256 => &ECDH_P256,
            EllipticCurve::P384 => &ECDH_P384,
            // EllipticCurve::X25519 => ECDH_X25519,
        }
    }

    pub fn affine_to_key(self, x: &[u8], y: &[u8]) -> Result<PublicKey, Error> {
        let name = self.to_openssl_name();
        let group = EcGroup::from_curve_name(name)?;

        let mut ctx = BigNumContext::new().unwrap();
        let x = BigNum::from_slice(x)?;
        let y = BigNum::from_slice(y)?;

        let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;
        // TODO(baloo): what is uncompressed?!
        let pub_key = key.public_key();

        Ok(PublicKey {
            curve: self,
            bytes: pub_key.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PublicKey {
    curve: EllipticCurve,
    bytes: Vec<u8>,
}

impl PublicKey {
    fn affine_coordinates(&self) -> Result<(ByteBuf, ByteBuf), Error> {
        let name = self.curve.to_openssl_name();
        let group = EcGroup::from_curve_name(name)?;

        let mut ctx = BigNumContext::new().unwrap();
        let point = EcPoint::from_bytes(&group, &self.bytes[..], &mut ctx).unwrap();

        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;

        point.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;
        //point.affine_coordinates_gf2m(&group, &mut x, &mut y, &mut ctx)?;

        Ok((x.to_vec().into(), y.to_vec().into()))
    }

    pub fn complete_handshake(&self) -> Result<ECDHSecret, ()> {
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

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut curve: Option<EllipticCurve> = None;
                let mut x: Option<ByteBuf> = None;
                let mut y: Option<ByteBuf> = None;

                while let Some(key) = map.next_key()? {
                    trace!("cose key {:?}", key);
                    match key {
                        -1 => {
                            if curve.is_some() {
                                return Err(de::Error::duplicate_field("curve"));
                            }
                            let value = map.next_value()?;
                            if let Ok(value) = EllipticCurve::from_u64(value) {
                                curve = Some(value);
                            } else {
                                return Err(de::Error::custom(format!(
                                    "unsupported curve {}",
                                    value
                                )));
                            }
                        }
                        -2 => {
                            if x.is_some() {
                                return Err(de::Error::duplicate_field("x"));
                            }
                            let value = map.next_value()?;

                            x = Some(value);
                        }
                        -3 => {
                            if y.is_some() {
                                return Err(de::Error::duplicate_field("y"));
                            }
                            let value = map.next_value()?;

                            y = Some(value);
                        }
                        _ => {
                            // TODO(baloo): need to check key_type (1)
                            //
                            // This unknown field should raise an error, but
                            // there is a couple of field I(baloo) do not understand
                            // yet. I(baloo) chose to ignore silently the
                            // error instead because of that
                            let value: Value = map.next_value()?;
                            trace!("cose unknown value {:?}:{:?}", key, value);
                        }
                    };
                }

                if let Some(curve) = curve {
                    if let Some(x) = x {
                        if let Some(y) = y {
                            let pub_key = curve.affine_to_key(&x[..], &y[..]).map_err(|e| {
                                de::Error::custom(format!("openssl error: {:?}", e))
                            })?;
                            Ok(pub_key)
                        } else {
                            Err(de::Error::custom("missing required field: y"))
                        }
                    } else {
                        Err(de::Error::custom("missing required field: x"))
                    }
                } else {
                    Err(de::Error::custom("missing required field: curve"))
                }
            }
        }

        deserializer.deserialize_bytes(PublicKeyVisitor)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry(&KEY_TYPE, &KEY_TYPE_EC2)?;
        map.serialize_entry(&-1, &(self.curve as u8))?;

        let (x, y) = self
            .affine_coordinates()
            .map_err(|e| S::Error::custom(format!("openssl error: {:?}", e)))?;

        map.serialize_entry(&-2, &x)?;
        map.serialize_entry(&-3, &y)?;
        map.end()
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
