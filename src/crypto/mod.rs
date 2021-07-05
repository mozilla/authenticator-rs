/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::ctap2::commands::CommandError;
use serde::{
    de::{Error as SerdeError, MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_bytes::ByteBuf;
use serde_cbor::Value;
use std::convert::TryFrom;
use std::fmt;

cfg_if::cfg_if! {
    if #[cfg(feature = "crypto_ring")] {
        #[path = "ring.rs"]
        pub mod imp;
    } else if #[cfg(feature = "crypto_openssl")] {
        #[path = "openssl.rs"]
        pub mod imp;
    } else {
        #[path = "nss.rs"]
        pub mod imp;
    }
}

pub(crate) use imp::*;

/// Errors that can be returned from COSE functions.
#[derive(Debug)]
pub enum CryptoError {
    // DecodingFailure,
    // LibraryFailure,
    // MalformedInput,
    // MissingHeader,
    // UnexpectedHeaderValue,
    // UnexpectedTag,
    // UnexpectedType,
    // Unimplemented,
    // VerificationFailed,
    // SigningFailed,
    // InvalidArgument,
    UnknownSignatureScheme,
    Backend(BackendError),
}

impl From<BackendError> for CryptoError {
    fn from(e: BackendError) -> Self {
        CryptoError::Backend(e)
    }
}

impl From<CryptoError> for CommandError {
    fn from(e: CryptoError) -> Self {
        CommandError::Crypto(e)
    }
}

// pub type CypherText = Vec<u8>;
// pub type PlainText = Vec<u8>;
// pub type Signature = Vec<u8>;

pub trait Key {
    fn curve(&self) -> SignatureAlgorithm;
    fn key(&self) -> &[u8];
}

/// An enum identifying supported signature algorithms.
/// Currently ES256 (ECDSA with P256 and SHA256), ES384 (ECDSA with P384 and SHA384)
/// ES512 (ECDSA with P521 and SHA512), and PS256 (RSASSA-PSS with SHA256)
/// are supported. Note that with PS256, the salt length is defined
/// to be 32 bytes.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    ES256 = 1,
    ES384 = 2,
    ES512 = 3,
    PS256 = 4,
}

impl TryFrom<u64> for SignatureAlgorithm {
    type Error = CryptoError;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(SignatureAlgorithm::ES256),
            2 => Ok(SignatureAlgorithm::ES384),
            3 => Ok(SignatureAlgorithm::ES512),
            4 => Ok(SignatureAlgorithm::PS256),
            _ => Err(CryptoError::UnknownSignatureScheme),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub curve: SignatureAlgorithm,
    // TODO(baloo): yeah, I know jcj :) I shouldn't be using bytes in asn.1 here :p
    pub bytes: Vec<u8>,
}

impl Key for PublicKey {
    fn curve(&self) -> SignatureAlgorithm {
        self.curve
    }

    fn key(&self) -> &[u8] {
        &self.bytes
    }
}

impl PublicKey {
    pub fn new(curve: SignatureAlgorithm, bytes: Vec<u8>) -> Self {
        PublicKey { curve, bytes }
    }
}

const KEY_TYPE: u8 = 1;

// https://tools.ietf.org/html/rfc8152#section-13
#[allow(dead_code)]
#[repr(u8)]
pub enum KeyType {
    OKP = 1,
    EC2 = 2,
    Symmetric = 4,
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut curve: Option<SignatureAlgorithm> = None;
                let mut x: Option<ByteBuf> = None;
                let mut y: Option<ByteBuf> = None;

                while let Some(key) = map.next_key()? {
                    trace!("cose key {:?}", key);
                    match key {
                        -1 => {
                            if curve.is_some() {
                                return Err(SerdeError::duplicate_field("curve"));
                            }
                            let value: u64 = map.next_value()?;
                            let val = SignatureAlgorithm::try_from(value).map_err(|_| {
                                SerdeError::custom(format!("unsupported curve {}", value))
                            })?;
                            curve = Some(val);
                        }
                        -2 => {
                            if x.is_some() {
                                return Err(SerdeError::duplicate_field("x"));
                            }
                            let value = map.next_value()?;

                            x = Some(value);
                        }
                        -3 => {
                            if y.is_some() {
                                return Err(SerdeError::duplicate_field("y"));
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
                            parse_key(curve, &x, &y).map_err(|e| {
                                SerdeError::custom(format!("crypto parsing error: {:?}", e))
                            })
                        } else {
                            Err(SerdeError::custom("missing required field: y"))
                        }
                    } else {
                        Err(SerdeError::custom("missing required field: x"))
                    }
                } else {
                    Err(SerdeError::custom("missing required field: curve"))
                }
            }
        }

        deserializer.deserialize_bytes(PublicKeyVisitor)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry(&KEY_TYPE, &(KeyType::EC2 as u8))?;
        map.serialize_entry(&-1, &(self.curve as u8))?;

        let (x, y) = serialize_key(self).map_err(|e| {
            serde::ser::Error::custom(format!(
                "crypto backend error while serializing PublicKey: {:?}",
                e
            ))
        })?;

        map.serialize_entry(&-2, &x)?;
        map.serialize_entry(&-3, &y)?;
        map.end()
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

#[derive(Clone)]
pub struct ECDHSecret {
    curve: SignatureAlgorithm,
    remote: PublicKey,
    my: PublicKey,
    shared_secret: Vec<u8>,
}

impl Key for ECDHSecret {
    fn curve(&self) -> SignatureAlgorithm {
        self.curve
    }

    fn key(&self) -> &[u8] {
        &self.shared_secret
    }
}

impl ECDHSecret {
    pub fn my_public_key(&self) -> &PublicKey {
        &self.my
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
    use super::{
        decrypt, encrypt, parse_key, serialize_key, test_encapsulate, PublicKey, SignatureAlgorithm,
    };
    use crate::util::decode_hex;
    use serde_bytes::ByteBuf;
    use serde_cbor::de::from_slice;

    #[test]
    fn test_serialize_key() {
        let key = PublicKey {
            curve: SignatureAlgorithm::PS256,
            bytes: vec![
                0x04, 0xfc, 0x9e, 0xd3, 0x6f, 0x7c, 0x1a, 0xa9, 0x15, 0xce, 0x3e, 0xa1, 0x77, 0xf0,
                0x75, 0x67, 0xf0, 0x7f, 0x16, 0xf9, 0x47, 0x9d, 0x95, 0xad, 0x8e, 0xd4, 0x97, 0x1d,
                0x33, 0x05, 0xe3, 0x1a, 0x80, 0x50, 0xb7, 0x33, 0xaf, 0x8c, 0x0b, 0x0e, 0xe1, 0xda,
                0x8d, 0xe0, 0xac, 0xf9, 0xd8, 0xe1, 0x32, 0x82, 0xf0, 0x63, 0xb7, 0xb3, 0x0d, 0x73,
                0xd4, 0xd3, 0x2c, 0x9a, 0xad, 0x6d, 0xfa, 0x8b, 0x27,
            ],
        };

        let (x, y) = serialize_key(&key).unwrap();

        assert_eq!(
            x,
            [
                0xfc, 0x9e, 0xd3, 0x6f, 0x7c, 0x1a, 0xa9, 0x15, 0xce, 0x3e, 0xa1, 0x77, 0xf0, 0x75,
                0x67, 0xf0, 0x7f, 0x16, 0xf9, 0x47, 0x9d, 0x95, 0xad, 0x8e, 0xd4, 0x97, 0x1d, 0x33,
                0x05, 0xe3, 0x1a, 0x80
            ]
        );
        assert_eq!(
            y,
            [
                0x50, 0xb7, 0x33, 0xaf, 0x8c, 0x0b, 0x0e, 0xe1, 0xda, 0x8d, 0xe0, 0xac, 0xf9, 0xd8,
                0xe1, 0x32, 0x82, 0xf0, 0x63, 0xb7, 0xb3, 0x0d, 0x73, 0xd4, 0xd3, 0x2c, 0x9a, 0xad,
                0x6d, 0xfa, 0x8b, 0x27
            ]
        );
    }

    #[test]
    fn test_parse_es256_serialize_key() {
        let key_data = decode_hex("A5010203262001215820A5FD5CE1B1C458C530A54FA61B31BF6B04BE8B97AFDE54DD8CBB69275A8A1BE1225820FA3A3231DD9DEED9D1897BE5A6228C59501E4BCD12975D3DFF730F01278EA61C");
        let key: PublicKey = from_slice(&key_data).unwrap();
        let (x, y) = serialize_key(&key).unwrap();
        assert_eq!(key.curve, SignatureAlgorithm::ES256);
        assert_eq!(
            x,
            ByteBuf::from(decode_hex(
                "A5FD5CE1B1C458C530A54FA61B31BF6B04BE8B97AFDE54DD8CBB69275A8A1BE1"
            ))
        );
        assert_eq!(
            y,
            ByteBuf::from(decode_hex(
                "FA3A3231DD9DEED9D1897BE5A6228C59501E4BCD12975D3DFF730F01278EA61C"
            ))
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_shared_secret() {
        let EC_PRIV =
            decode_hex("7452E599FEE739D8A653F6A507343D12D382249108A651402520B72F24FE7684");
        let EC_PUB_X =
            decode_hex("44D78D7989B97E62EA993496C9EF6E8FD58B8B00715F9A89153DDD9C4657E47F");
        let EC_PUB_Y =
            decode_hex("EC802EE7D22BD4E100F12E48537EB4E7E96ED3A47A0A3BD5F5EEAB65001664F9");
        let DEV_PUB_X =
            decode_hex("0501D5BC78DA9252560A26CB08FCC60CBE0B6D3B8E1D1FCEE514FAC0AF675168");
        let DEV_PUB_Y =
            decode_hex("D551B3ED46F665731F95B4532939C25D91DB7EB844BD96D4ABD4083785F8DF47");
        let SHARED = decode_hex("c42a039d548100dfba521e487debcbbb8b66bb7496f8b1862a7a395ed83e1a1c");
        let TOKEN_ENC = decode_hex("7A9F98E31B77BE90F9C64D12E9635040");
        let TOKEN = decode_hex("aff12c6dcfbf9df52f7a09211e8865cd");
        //let PIN_HASH_ENC = decode_hex("afe8327ce416da8ee3d057589c2ce1a9");

        let peer_key = parse_key(SignatureAlgorithm::PS256, &DEV_PUB_X, &DEV_PUB_Y).unwrap();
        // TODO: This fails of course, as private key is generated on the fly.
        //       Need some nice way to hand in private and public keypair for testing
        let my_pub_key = parse_key(SignatureAlgorithm::PS256, &EC_PUB_X, &EC_PUB_Y).unwrap();
        let shared_secret = test_encapsulate(&peer_key, my_pub_key.as_ref(), &EC_PRIV).unwrap();
        assert_eq!(shared_secret.shared_secret, SHARED);

        let token_enc = encrypt(&shared_secret, &TOKEN).unwrap();
        assert_eq!(token_enc, TOKEN_ENC);

        let token = decrypt(&shared_secret, &TOKEN_ENC).unwrap();
        assert_eq!(token, TOKEN);
    }
}
