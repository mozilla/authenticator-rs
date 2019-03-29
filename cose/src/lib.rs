#[macro_use]
extern crate log;
extern crate openssl;
extern crate ring;
extern crate serde;
extern crate serde_bytes;
extern crate serde_cbor;
extern crate sha2;
extern crate untrusted;

use std::error::Error as StdErrorT;
use std::fmt;

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use ring::agreement::{Algorithm, ECDH_P256, ECDH_P384};
use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde::ser::{Error as SerdeSerError, Serialize, SerializeMap, Serializer};
use serde_bytes::ByteBuf;
use serde_cbor::Value;

pub mod agreement;

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
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

const KEY_TYPE: u8 = 1;

// https://tools.ietf.org/html/rfc8152#section-13
#[repr(u8)]
enum KeyType {
    OKP = 1,
    EC2 = 2,
    Symmetric = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    curve: EllipticCurve,
    // TODO(baloo): yeah, I know jcj :) I shouldn't be using bytes in asn.1 here :p
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
        map.serialize_entry(&KEY_TYPE, &(KeyType::EC2 as u8))?;
        map.serialize_entry(&-1, &(self.curve as u8))?;

        let (x, y) = self
            .affine_coordinates()
            .map_err(|e| S::Error::custom(format!("openssl error: {:?}", e)))?;

        map.serialize_entry(&-2, &x)?;
        map.serialize_entry(&-3, &y)?;
        map.end()
    }
}
