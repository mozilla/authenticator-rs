use std::fmt;

use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json as json;
use sha2::{Digest, Sha256};

#[derive(Debug, Eq, PartialEq)]
pub enum Version {
    //    CTAP1,
    CTAP2,
}

/// https://w3c.github.io/webauthn/#dom-collectedclientdata-tokenbinding
// tokenBinding, of type TokenBinding
//
//    This OPTIONAL member contains information about the state of the Token
//    Binding protocol [TokenBinding] used when communicating with the Relying
//    Party. Its absence indicates that the client doesn’t support token
//    binding.
//
//    status, of type TokenBindingStatus
//
//        This member is one of the following:
//
//        supported
//
//            Indicates the client supports token binding, but it was not
//            negotiated when communicating with the Relying Party.
//
//        present
//
//            Indicates token binding was used when communicating with the
//            Relying Party. In this case, the id member MUST be present.
//
//    id, of type DOMString
//
//        This member MUST be present if status is present, and MUST be a
//        base64url encoding of the Token Binding ID that was used when
//        communicating with the Relying Party.
#[derive(Debug, Clone)]
pub enum TokenBinding {
    Present(Vec<u8>),
    Supported,
}

impl Serialize for TokenBinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        match *self {
            TokenBinding::Supported => {
                map.serialize_entry(&"status", &"supported")?;
            }
            TokenBinding::Present(ref v) => {
                // The term Base64url Encoding refers to the base64 encoding
                // using the URL- and filename-safe character set defined in
                // Section 5 of [RFC4648], with all trailing '=' characters
                // omitted (as permitted by Section 3.2) and without the
                // inclusion of any line breaks, whitespace, or other additional
                // characters.
                let b64 = base64::encode_config(&v[..], base64::URL_SAFE_NO_PAD);

                map.serialize_entry(&"status", "present")?;
                map.serialize_entry(&"id", &b64)?;
            }
        }
        map.end()
    }
}

/// https://w3c.github.io/webauthn/#dom-collectedclientdata-type
// type, of type DOMString
//
//    This member contains the string "webauthn.create" when creating new
//    credentials, and "webauthn.get" when getting an assertion from an
//    existing credential. The purpose of this member is to prevent certain
//    types of signature confusion attacks (where an attacker substitutes one
//    legitimate signature for another).
#[derive(Debug, Copy, Clone)]
pub enum WebauthnType {
    Create,
    Get,
}

impl Serialize for WebauthnType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            WebauthnType::Create => serializer.serialize_str(&"webauthn.create"),
            WebauthnType::Get => serializer.serialize_str(&"webauthn.get"),
        }
    }
}

#[derive(Serialize, Clone)]
pub struct Challenge(Vec<u8>);

impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = base64::encode_config(&self.0[..], base64::URL_SAFE_NO_PAD);
        write!(f, "Challenge({})", value)
    }
}

impl From<Vec<u8>> for Challenge {
    fn from(v: Vec<u8>) -> Challenge {
        Challenge(v)
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct CollectedClientData {
    #[serde(rename = "type")]
    pub type_: WebauthnType,
    pub challenge: Challenge,
    pub origin: String,
    #[serde(rename = "tokenBinding", skip_serializing_if = "Option::is_none")]
    pub token_binding: Option<TokenBinding>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ClientDataHash([u8; 32]);

impl PartialEq<[u8]> for ClientDataHash {
    fn eq(&self, other: &[u8]) -> bool {
        self.0.eq(other)
    }
}

impl AsRef<[u8]> for ClientDataHash {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Serialize for ClientDataHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl CollectedClientData {
    pub fn hash(&self) -> json::Result<ClientDataHash> {
        // TODO(baloo): this could use a bit more spec, there is no ordering specified. Are spaces
        //              allowed? Is this needed for support between vendors? Does it need to be
        //              stable across browsers? Maybe send an email to the mailing list.
        //              https://w3c.github.io/webauthn/#collectedclientdata-json-serialized-client-data
        let data = json::to_vec(&self)?;

        let mut hasher = Sha256::new();
        hasher.input(&data[..]);

        let mut output = [0u8; 32];
        output.copy_from_slice(hasher.result().as_slice());

        Ok(ClientDataHash(output))
    }
}

#[cfg(test)]
mod test {
    use super::{Challenge, CollectedClientData, TokenBinding, WebauthnType};
    use serde_json as json;

    #[test]
    fn test_token_binding_status() {
        let tok = TokenBinding::Present(vec![0x00, 0x01, 0x02, 0x03]);

        let json_value = json::to_string(&tok).unwrap();
        assert_eq!(json_value, "{\"status\":\"present\",\"id\":\"AAECAw\"}");

        let tok = TokenBinding::Supported;

        let json_value = json::to_string(&tok).unwrap();
        assert_eq!(json_value, "{\"status\":\"supported\"}");
    }

    #[test]
    fn test_webauthn_type() {
        let t = WebauthnType::Create;

        let json_value = json::to_string(&t).unwrap();
        assert_eq!(json_value, "\"webauthn.create\"");

        let t = WebauthnType::Get;
        let json_value = json::to_string(&t).unwrap();
        assert_eq!(json_value, "\"webauthn.get\"");
    }

    #[test]
    fn test_collected_client_data() {
        let client_data = CollectedClientData {
            type_: WebauthnType::Create,
            challenge: Challenge(vec![0x00, 0x01, 0x02, 0x03]),
            origin: String::from("example.com"),
            token_binding: Some(TokenBinding::Present(vec![0x00, 0x01, 0x02, 0x03])),
        };

        assert_eq!(
            &client_data.hash().unwrap(),
            &hex!("c1dd355f3c816923e057ca038dbaadb85f9555cfc7629b9d5366975380d7694f")[..]
        );
    }
}
