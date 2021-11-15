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

/// Errors that can be returned from COSE functions.
#[derive(Debug, PartialEq)]
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

    fn try_from(value: u64) -> Result<Self, Self::Error> {
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
impl PublicKey {
    fn affine_coordinates(&self) -> Result<(ByteBuf, ByteBuf), CommandError> {
        unimplemented!();
        /*
                let name = self.curve.to_openssl_name();
                let group = EcGroup::from_curve_name(name)?;

                let mut ctx = BigNumContext::new().unwrap();
                let point = EcPoint::from_bytes(&group, &self.bytes, &mut ctx).unwrap();

                let mut x = BigNum::new()?;
                let mut y = BigNum::new()?;

                point.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;
                //point.affine_coordinates_gf2m(&group, &mut x, &mut y, &mut ctx)?;

                Ok((x.to_vec().into(), y.to_vec().into()))
        */
    }

    pub fn new(curve: SignatureAlgorithm, bytes: Vec<u8>) -> Self {
        PublicKey { curve, bytes }
    }
}

const KEY_TYPE: u8 = 1;

// https://tools.ietf.org/html/rfc8152#section-13
#[repr(u8)]
pub enum KeyType {
    OKP = 1,
    EC2 = 2,
    Symmetric = 4,
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

                if let Some(_curve) = curve {
                    if let Some(_x) = x {
                        if let Some(_y) = y {
                            unimplemented!();
                        //                             let pub_key = curve.affine_to_key(&x, &y).map_err(|e| {
                        //                                 SerdeError::custom(format!("nss error: {:?}", e))
                        //                             })?;
                        //                             Ok(pub_key)
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
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry(&KEY_TYPE, &(KeyType::EC2 as u8))?;
        map.serialize_entry(&-1, &(self.curve as u8))?;

        let (x, y) = self
            .affine_coordinates()
            .map_err(|e| serde::ser::Error::custom(format!("NSS error: {:?}", e)))?;

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

impl ECDHSecret {
    pub fn my_public_key(&self) -> &PublicKey {
        &self.my
    }

    pub fn shared_secret(&self) -> &[u8] {
        self.shared_secret.as_ref()
    }

    pub fn encrypt(&self, _input: &[u8], _iv: &[u8]) -> Result<Vec<u8>, CommandError> {
        unimplemented!();
        /*let cipher = Cipher::aes_256_cbc();

        // TODO(baloo): This might trigger a panic if size is not big enough
        let mut output = vec![0; input.len() * 2];
        output.resize(input.len() * 2, 0);
        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, self.0.shared_secret(), Some(iv))
            .map_err(Error::Openssl)?;
        encrypter.pad(false);
        let mut out_size = 0;
        out_size += encrypter.update(input, output.as_mut_slice())?;
        out_size += encrypter.finalize(output.as_mut_slice())?;
        output.truncate(out_size);
        Ok(output)*/
    }

    pub fn decrypt(&self, _input: &[u8], _iv: &[u8]) -> Result<Vec<u8>, CommandError> {
        unimplemented!();
        /*let cipher = Cipher::aes_256_cbc();

        // TODO(baloo): This might trigger a panic if size is not big enough
        let mut output = vec![0; input.len() * 2];
        output.resize(input.len() * 2, 0);
        let mut encrypter = Crypter::new(cipher, Mode::Decrypt, self.0.shared_secret(), Some(iv))
            .map_err(Error::Openssl)?;
        encrypter.pad(false);
        let mut out_size = 0;
        out_size += encrypter.update(input, output.as_mut_slice())?;
        out_size += encrypter.finalize(output.as_mut_slice())?;
        output.truncate(out_size);

        Ok(output)*/
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
