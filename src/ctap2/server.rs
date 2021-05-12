use serde_bytes::ByteBuf;
#[cfg(test)]
use serde_cbor::{error, ser};
use sha2::{Digest, Sha256};
use std::fmt;

#[cfg(test)]
use serde::de::MapAccess;
use serde::{
    de::{Error as SerdeError, Unexpected, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::AuthenticatorTransports;
use crate::KeyHandle;

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct RpIdHash(pub [u8; 32]);

impl fmt::Debug for RpIdHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = base64::encode_config(&self.0, base64::URL_SAFE_NO_PAD);
        write!(f, "RpIdHash({})", value)
    }
}

impl AsRef<[u8]> for RpIdHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl RpIdHash {
    pub fn from(src: &[u8]) -> Result<RpIdHash, ()> {
        let mut payload = [0u8; 32];
        if src.len() != payload.len() {
            Err(())
        } else {
            payload.copy_from_slice(src);
            Ok(RpIdHash(payload))
        }
    }
}

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
pub struct RelyingParty {
    // TODO(baloo): spec is wrong !!!!111
    //              https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#commands
    //              in the example "A PublicKeyCredentialRpEntity DOM object defined as follows:"
    //              inconsistent with https://w3c.github.io/webauthn/#sctn-rp-credential-params
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

impl RelyingParty {
    #[cfg(test)]
    pub fn to_ctap2(&self) -> Result<Vec<u8>, error::Error> {
        ser::to_vec(self)
    }

    pub fn hash(&self) -> RpIdHash {
        let mut hasher = Sha256::new();
        hasher.input(&self.id);

        let mut output = [0u8; 32];
        output.copy_from_slice(&hasher.result().as_slice());

        RpIdHash(output)
    }
}

// TODO(baloo): should we rename this PublicKeyCredentialUserEntity ?
#[derive(Debug, Serialize, Clone, Eq, PartialEq, Deserialize)]
pub struct User {
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "displayName")]
    pub display_name: Option<String>,
}

#[cfg(test)]
impl User {
    pub fn to_ctap2(&self) -> Result<Vec<u8>, error::Error> {
        ser::to_vec(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// see: https://www.iana.org/assignments/cose/cose.xhtml#table-algorithms
// TODO(baloo): could probably use a more generic approach, need to see this
//              whenever we introduce the firefox-side api
pub enum Alg {
    ES256,
    RS256,
}

impl Serialize for Alg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Alg::ES256 => serializer.serialize_i8(-7),
            Alg::RS256 => serializer.serialize_i16(-257),
        }
    }
}

impl<'de> Deserialize<'de> for Alg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AlgVisitor;

        impl<'de> Visitor<'de> for AlgVisitor {
            type Value = Alg;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a signed integer")
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                match v {
                    -7 => Ok(Alg::ES256),
                    -257 => Ok(Alg::RS256),
                    v => Err(SerdeError::invalid_value(Unexpected::Signed(v), &self)),
                }
            }
        }

        deserializer.deserialize_any(AlgVisitor)
    }
}

#[derive(Debug, Clone)]
pub struct PublicKeyCredentialParameters {
    pub alg: Alg,
}

impl Serialize for PublicKeyCredentialParameters {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("alg", &self.alg)?;
        map.serialize_entry("type", "public-key")?;
        map.end()
    }
}

#[cfg(test)]
impl<'de> Deserialize<'de> for PublicKeyCredentialParameters {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyCredentialParametersVisitor;

        impl<'de> Visitor<'de> for PublicKeyCredentialParametersVisitor {
            type Value = PublicKeyCredentialParameters;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut found_type = false;
                let mut alg = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "alg" => {
                            if alg.is_some() {
                                return Err(SerdeError::duplicate_field("alg"));
                            }

                            alg = Some(map.next_value()?);
                        }
                        "type" => {
                            if found_type {
                                return Err(SerdeError::duplicate_field("type"));
                            }

                            let v: &str = map.next_value()?;
                            if v != "public-key" {
                                return Err(SerdeError::custom(format!("invalid value: {}", v)));
                            }
                            found_type = true;
                        }
                        v => {
                            return Err(SerdeError::unknown_field(v, &[]));
                        }
                    }
                }

                if !found_type {
                    return Err(SerdeError::missing_field("type"));
                }

                let alg = alg.ok_or(SerdeError::missing_field("alg"))?;

                Ok(PublicKeyCredentialParameters { alg })
            }
        }

        deserializer.deserialize_bytes(PublicKeyCredentialParametersVisitor)
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    USB,
    NFC,
    BLE,
    Internal,
}

impl From<AuthenticatorTransports> for Vec<Transport> {
    fn from(t: AuthenticatorTransports) -> Self {
        let mut transports = Vec::new();
        if t.contains(AuthenticatorTransports::USB) {
            transports.push(Transport::USB);
        }
        if t.contains(AuthenticatorTransports::NFC) {
            transports.push(Transport::NFC);
        }
        if t.contains(AuthenticatorTransports::BLE) {
            transports.push(Transport::BLE);
        }

        transports
    }
}

#[derive(Debug)]
pub struct PublicKeyCredentialDescriptor {
    pub id: Vec<u8>,
    pub transports: Vec<Transport>,
}

impl Serialize for PublicKeyCredentialDescriptor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("type", "public-key")?;
        map.serialize_entry("id", &ByteBuf::from(self.id.clone()))?;
        map.serialize_entry("transports", &self.transports)?;
        map.end()
    }
}

#[cfg(test)]
impl<'de> Deserialize<'de> for PublicKeyCredentialDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyCredentialDescriptorVisitor;

        impl<'de> Visitor<'de> for PublicKeyCredentialDescriptorVisitor {
            type Value = PublicKeyCredentialDescriptor;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut found_type = false;
                let mut id = None;
                let mut transports = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "id" => {
                            if id.is_some() {
                                return Err(SerdeError::duplicate_field("id"));
                            }

                            id = Some(map.next_value()?);
                        }
                        "transports" => {
                            if transports.is_some() {
                                return Err(SerdeError::duplicate_field("transports"));
                            }

                            transports = Some(map.next_value()?);
                        }
                        "type" => {
                            if found_type {
                                return Err(SerdeError::duplicate_field("type"));
                            }

                            let v: &str = map.next_value()?;
                            if v != "public-key" {
                                return Err(SerdeError::custom(format!("invalid value: {}", v)));
                            }
                            found_type = true;
                        }
                        v => {
                            return Err(SerdeError::unknown_field(v, &[]));
                        }
                    }
                }

                if !found_type {
                    return Err(SerdeError::missing_field("type"));
                }

                let id = id.ok_or(SerdeError::missing_field("id"))?;
                let transports = transports.ok_or(SerdeError::missing_field("transports"))?;

                Ok(PublicKeyCredentialDescriptor { id, transports })
            }
        }

        deserializer.deserialize_bytes(PublicKeyCredentialDescriptorVisitor)
    }
}

impl From<&KeyHandle> for PublicKeyCredentialDescriptor {
    fn from(kh: &KeyHandle) -> Self {
        Self {
            id: kh.credential.clone(),
            transports: kh.transports.into(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{
        Alg, PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, RelyingParty, Transport,
        User,
    };

    #[test]
    fn serialize_rp() {
        let rp = RelyingParty {
            id: String::from("Acme"),
            name: None,
            icon: None,
        };

        let payload = rp.to_ctap2();
        let payload = payload.unwrap();
        assert_eq!(
            &payload,
            &[
                0xa1, // map(1)
                0x62, // text(2)
                0x69, 0x64, // "id"
                0x64, // text(4)
                0x41, 0x63, 0x6d, 0x65
            ]
        );
    }

    #[test]
    fn serialize_user() {
        let user = User {
            id: vec![
                0x30, 0x82, 0x01, 0x93, 0x30, 0x82, 0x01, 0x38, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x30,
                0x82, 0x01, 0x93, 0x30, 0x82, 0x01, 0x38, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x30, 0x82,
                0x01, 0x93, 0x30, 0x82,
            ],
            icon: Some(String::from("https://pics.example.com/00/p/aBjjjpqPb.png")),
            name: String::from("johnpsmith@example.com"),
            display_name: Some(String::from("John P. Smith")),
        };

        let payload = user.to_ctap2();
        println!("payload = {:?}", payload);
        let payload = payload.unwrap();
        assert_eq!(
            payload,
            vec![
                0xa4, // map(4)
                0x62, // text(2)
                0x69, 0x64, // "id"
                0x58, 0x20, // bytes(32)
                0x30, 0x82, 0x01, 0x93, 0x30, 0x82, 0x01, 0x38, 0xa0, 0x03, // userid
                0x02, 0x01, 0x02, 0x30, 0x82, 0x01, 0x93, 0x30, 0x82, 0x01, // ...
                0x38, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x30, 0x82, 0x01, 0x93, // ...
                0x30, 0x82, // ...
                0x64, // text(4)
                0x69, 0x63, 0x6f, 0x6e, // "icon"
                0x78, 0x2b, // text(43)
                0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x70,
                0x69, // "https://pics.example.com/00/p/aBjjjpqPb.png"
                0x63, 0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // ...
                0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x30, 0x30, 0x2f, 0x70, 0x2f, // ...
                0x61, 0x42, 0x6a, 0x6a, 0x6a, 0x70, 0x71, 0x50, 0x62, 0x2e, // ...
                0x70, 0x6e, 0x67, // ...
                0x64, // text(4)
                0x6e, 0x61, 0x6d, 0x65, // "name"
                0x76, // text(22)
                0x6a, 0x6f, 0x68, 0x6e, 0x70, 0x73, 0x6d, 0x69, 0x74,
                0x68, // "johnpsmith@example.com"
                0x40, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, // ...
                0x6f, 0x6d, // ...
                0x6b, // text(11)
                0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, // "displayName"
                0x65, // ...
                0x6d, // text(13)
                0x4a, 0x6f, 0x68, 0x6e, 0x20, 0x50, 0x2e, 0x20, 0x53, 0x6d, // "John P. Smith"
                0x69, 0x74, 0x68, // ...
            ]
        );
    }

    #[test]
    fn serialize_user_noicon_nodisplayname() {
        let user = User {
            id: vec![
                0x30, 0x82, 0x01, 0x93, 0x30, 0x82, 0x01, 0x38, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x30,
                0x82, 0x01, 0x93, 0x30, 0x82, 0x01, 0x38, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x30, 0x82,
                0x01, 0x93, 0x30, 0x82,
            ],
            icon: None,
            name: String::from("johnpsmith@example.com"),
            display_name: None,
        };

        let payload = user.to_ctap2();
        println!("payload = {:?}", payload);
        let payload = payload.unwrap();
        assert_eq!(
            payload,
            vec![
                0xa2, // map(2)
                0x62, // text(2)
                0x69, 0x64, // "id"
                0x58, 0x20, // bytes(32)
                0x30, 0x82, 0x01, 0x93, 0x30, 0x82, 0x01, 0x38, 0xa0, 0x03, // userid
                0x02, 0x01, 0x02, 0x30, 0x82, 0x01, 0x93, 0x30, 0x82, 0x01, // ...
                0x38, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x30, 0x82, 0x01, 0x93, // ...
                0x30, 0x82, // ...
                0x64, // text(4)
                0x6e, 0x61, 0x6d, 0x65, // "name"
                0x76, // text(22)
                0x6a, 0x6f, 0x68, 0x6e, 0x70, 0x73, 0x6d, 0x69, 0x74,
                0x68, // "johnpsmith@example.com"
                0x40, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, // ...
                0x6f, 0x6d, // ...
            ]
        );
    }

    use serde_cbor::ser;

    #[test]
    fn public_key() {
        let keys = vec![
            PublicKeyCredentialParameters { alg: Alg::ES256 },
            PublicKeyCredentialParameters { alg: Alg::RS256 },
        ];

        let payload = ser::to_vec(&keys);
        println!("payload = {:?}", payload);
        let payload = payload.unwrap();
        assert_eq!(
            payload,
            vec![
                0x82, // array(2)
                0xa2, // map(2)
                0x63, // text(3)
                0x61, 0x6c, 0x67, // "alg"
                0x26, // -7 (ES256)
                0x64, // text(4)
                0x74, 0x79, 0x70, 0x65, // "type"
                0x6a, // text(10)
                0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, // "public-key"
                0x2D, 0x6B, 0x65, 0x79, // ...
                0xa2, // map(2)
                0x63, // text(3)
                0x61, 0x6c, 0x67, // "alg"
                0x39, 0x01, 0x00, // -257 (RS256)
                0x64, // text(4)
                0x74, 0x79, 0x70, 0x65, // "type"
                0x6a, // text(10)
                0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, // "public-key"
                0x2D, 0x6B, 0x65, 0x79 // ...
            ]
        );
    }

    #[test]
    fn public_key_desc() {
        let key = PublicKeyCredentialDescriptor {
            id: vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
            transports: vec![Transport::BLE, Transport::USB],
        };

        let payload = ser::to_vec(&key);
        println!("payload = {:?}", payload);
        let payload = payload.unwrap();

        assert_eq!(
            payload,
            vec![
                0xa3, // map(3)
                0x64, // text(4)
                0x74, 0x79, 0x70, 0x65, // "type"
                0x6a, // text(10)
                0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, // "public-key"
                0x2D, 0x6B, 0x65, 0x79, // ...
                0x62, // text(2)
                0x69, 0x64, // "id"
                0x58, 0x20, // bytes(32)
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // key id
                0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // ...
                0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, // ...
                0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // ...
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, // ...
                0x1e, 0x1f, // ...
                0x6a, // text(10)
                0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, // "transports"
                0x6f, 0x72, 0x74, 0x73, // ...
                0x82, // array(2)
                0x63, // text(3)
                0x62, 0x6c, 0x65, // "ble"
                0x63, // text(3)
                0x75, 0x73, 0x62 // "usb"
            ]
        );
    }
}
