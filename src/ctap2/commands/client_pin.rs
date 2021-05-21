use super::{get_info::AuthenticatorInfo, Command, CommandError, RequestCtap2, StatusCode};
use crate::ctap2::client_data::ClientDataHash;
use crate::ctap2::crypto::{ECDHSecret, PublicKey};
use crate::transport::errors::HIDError;
use crate::u2ftypes::U2FDevice;
use serde::{
    de::{Error as SerdeError, MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_bytes::ByteBuf;
use serde_cbor::de::from_slice;
use serde_cbor::ser::to_vec;
use serde_cbor::Value;
use sha2::{Digest, Sha256};
use std::error::Error as StdErrorT;
use std::fmt;

// use serde::Deserialize; cfg[test]

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum PINSubcommand {
    GetRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPIN = 0x03,
    ChangePIN = 0x04,
    GetPINToken = 0x05,
}

#[derive(Debug)]
pub(crate) struct ClientPIN {
    pin_protocol: u8,
    subcommand: PINSubcommand,
    key_agreement: Option<PublicKey>,
    pin_auth: Option<[u8; 16]>,
    new_pin_enc: Option<ByteBuf>,
    pin_hash_enc: Option<ByteBuf>,
}

impl Default for ClientPIN {
    fn default() -> Self {
        ClientPIN {
            pin_protocol: 0,
            subcommand: PINSubcommand::GetRetries,
            key_agreement: None,
            pin_auth: None,
            new_pin_enc: None,
            pin_hash_enc: None,
        }
    }
}

impl Serialize for ClientPIN {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Need to define how many elements are going to be in the map
        // beforehand
        let mut map_len = 2;
        if self.key_agreement.is_some() {
            map_len += 1;
        }
        if self.pin_auth.is_some() {
            map_len += 1;
        }
        if self.new_pin_enc.is_some() {
            map_len += 1;
        }
        if self.pin_hash_enc.is_some() {
            map_len += 1;
        }

        let mut map = serializer.serialize_map(Some(map_len))?;
        map.serialize_entry(&1, &self.pin_protocol)?;
        let command: u8 = self.subcommand as u8;
        map.serialize_entry(&2, &command)?;
        if let Some(ref key_agreement) = self.key_agreement {
            map.serialize_entry(&3, key_agreement)?;
        }
        if let Some(ref pin_auth) = self.pin_auth {
            map.serialize_entry(&4, pin_auth)?;
        }
        if let Some(ref new_pin_enc) = self.new_pin_enc {
            map.serialize_entry(&5, new_pin_enc)?;
        }
        if let Some(ref pin_hash_enc) = self.pin_hash_enc {
            map.serialize_entry(&6, pin_hash_enc)?;
        }

        map.end()
    }
}

pub(crate) trait ClientPINSubCommand {
    type Output;
    fn as_client_pin(&self) -> Result<ClientPIN, CommandError>;
    fn parse_response_payload(&self, input: &[u8]) -> Result<Self::Output, CommandError>;
}

struct ClientPinResponse {
    key_agreement: Option<PublicKey>,
    pin_token: Option<EncryptedPinToken>,
    /// Number of PIN attempts remaining before lockout.
    _retries: Option<u8>,
}

impl<'de> Deserialize<'de> for ClientPinResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ClientPinResponseVisitor;

        impl<'de> Visitor<'de> for ClientPinResponseVisitor {
            type Value = ClientPinResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut key_agreement = None;
                let mut pin_token = None;
                let mut retries = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        1 => {
                            if key_agreement.is_some() {
                                return Err(SerdeError::duplicate_field("key_agreement"));
                            }
                            key_agreement = map.next_value()?;
                        }
                        2 => {
                            if pin_token.is_some() {
                                return Err(SerdeError::duplicate_field("pin_token"));
                            }
                            pin_token = map.next_value()?;
                        }
                        3 => {
                            if retries.is_some() {
                                return Err(SerdeError::duplicate_field("retries"));
                            }
                            retries = Some(map.next_value()?);
                        }
                        k => return Err(M::Error::custom(format!("unexpected key: {:?}", k))),
                    }
                }
                Ok(ClientPinResponse {
                    key_agreement,
                    pin_token,
                    _retries: retries,
                })
            }
        }

        deserializer.deserialize_bytes(ClientPinResponseVisitor)
    }
}

#[derive(Debug)]
pub struct GetKeyAgreement {
    pin_protocol: u8,
}

impl GetKeyAgreement {
    pub fn new(info: &AuthenticatorInfo) -> Result<Self, CommandError> {
        if info.pin_protocols.contains(&1) {
            Ok(GetKeyAgreement { pin_protocol: 1 })
        } else {
            Err(CommandError::UnsupportedPinProtocol)
        }
    }
}

impl ClientPINSubCommand for GetKeyAgreement {
    type Output = KeyAgreement;

    fn as_client_pin(&self) -> Result<ClientPIN, CommandError> {
        Ok(ClientPIN {
            pin_protocol: self.pin_protocol,
            subcommand: PINSubcommand::GetKeyAgreement,
            ..ClientPIN::default()
        })
    }

    fn parse_response_payload(&self, input: &[u8]) -> Result<Self::Output, CommandError> {
        let value: Value = from_slice(input).map_err(CommandError::Parsing)?;
        debug!("GetKeyAgreement::parse_response_payload {:?}", value);

        let get_pin_response: ClientPinResponse =
            from_slice(input).map_err(CommandError::Parsing)?;
        if let Some(key_agreement) = get_pin_response.key_agreement {
            Ok(KeyAgreement(key_agreement))
        } else {
            Err(CommandError::MissingRequiredField("key_agreement"))
        }
    }
}

#[derive(Debug)]
pub struct GetPinToken<'sc, 'pin> {
    pin_protocol: u8,
    shared_secret: &'sc ECDHSecret,
    pin: &'pin Pin,
}

impl<'sc, 'pin> GetPinToken<'sc, 'pin> {
    pub fn new(
        info: &AuthenticatorInfo,
        shared_secret: &'sc ECDHSecret,
        pin: &'pin Pin,
    ) -> Result<Self, CommandError> {
        if info.pin_protocols.contains(&1) {
            Ok(GetPinToken {
                pin_protocol: 1,
                shared_secret,
                pin,
            })
        } else {
            Err(CommandError::UnsupportedPinProtocol)
        }
    }
}

impl<'sc, 'pin> ClientPINSubCommand for GetPinToken<'sc, 'pin> {
    type Output = PinToken;

    fn as_client_pin(&self) -> Result<ClientPIN, CommandError> {
        let iv = [0u8; 16];
        let input = self.pin.for_pin_token();
        trace!("pin_hash = {:#04X?}", &input.as_ref());
        let pin_hash_enc = self.shared_secret.encrypt(input.as_ref(), &iv)?;
        trace!("pin_hash_enc = {:#04X?}", &pin_hash_enc);

        Ok(ClientPIN {
            pin_protocol: self.pin_protocol,
            subcommand: PINSubcommand::GetPINToken,
            key_agreement: Some(self.shared_secret.my_public_key().clone()),
            pin_hash_enc: Some(ByteBuf::from(pin_hash_enc)),
            ..ClientPIN::default()
        })
    }

    fn parse_response_payload(&self, input: &[u8]) -> Result<Self::Output, CommandError> {
        let value: Value = from_slice(input).map_err(CommandError::Parsing)?;
        debug!("GetKeyAgreement::parse_response_payload {:?}", value);

        let get_pin_response: ClientPinResponse =
            from_slice(input).map_err(CommandError::Parsing)?;
        if let Some(encrypted_pin_token) = get_pin_response.pin_token {
            let iv = [0u8; 16];
            let pin_token = self
                .shared_secret
                .decrypt(encrypted_pin_token.as_ref(), &iv)?;
            let pin_token = PinToken(pin_token);
            Ok(pin_token)
        } else {
            Err(CommandError::MissingRequiredField("key_agreement"))
        }
    }
}

impl<T> RequestCtap2 for T
where
    T: ClientPINSubCommand,
    T: fmt::Debug,
{
    type Output = <T as ClientPINSubCommand>::Output;

    fn command() -> Command {
        Command::ClientPin
    }

    fn wire_format<Dev>(&self, _dev: &mut Dev) -> Result<Vec<u8>, HIDError>
    where
        Dev: U2FDevice,
    {
        let client_pin = self.as_client_pin()?;
        let output = to_vec(&client_pin).map_err(CommandError::Serialization)?;
        trace!("client subcommmand: {:#04X?}", &output);

        Ok(output)
    }

    fn handle_response_ctap2<Dev>(
        &self,
        _dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, HIDError>
    where
        Dev: U2FDevice,
    {
        trace!("Client pin subcomand response:{:#04X?}", &input);

        if input.is_empty() {
            return Err(CommandError::InputTooSmall).map_err(HIDError::Command);
        }
        let status: StatusCode = input[0].into();
        debug!("response status code: {:?}", status);
        if input.len() > 1 {
            if status.is_ok() {
                <T as ClientPINSubCommand>::parse_response_payload(self, &input[1..])
                    .map_err(HIDError::Command)
            } else {
                let data: Value = from_slice(&input[1..]).map_err(CommandError::Parsing)?;
                Err(CommandError::StatusCode(status, Some(data))).map_err(HIDError::Command)
            }
        } else if status.is_ok() {
            Err(CommandError::InputTooSmall).map_err(HIDError::Command)
        } else {
            Err(CommandError::StatusCode(status, None)).map_err(HIDError::Command)
        }
    }
}

#[derive(Debug)]
pub struct KeyAgreement(PublicKey);

impl KeyAgreement {
    pub fn shared_secret(&self) -> Result<ECDHSecret, CommandError> {
        unimplemented!();
        //         self.0
        //             .complete_handshake()
        //             .map_err(|_| Error::ECDH)
        //             .map(ECDHSecret)
    }
}

#[derive(Debug, Deserialize)]
pub struct EncryptedPinToken(ByteBuf);

impl AsRef<[u8]> for EncryptedPinToken {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug)]
pub struct PinToken(Vec<u8>);

impl PinToken {
    pub fn auth(&self, _client_hash_data: &ClientDataHash) -> Result<PinAuth, PinError> {
        if self.0.len() < 4 {
            return Err(PinError::PinIsTooShort);
        }

        let bytes = self.0.as_slice();
        if bytes.len() > 64 {
            return Err(PinError::PinIsTooLong(bytes.len()));
        }

        unimplemented!();
        /*let mut mac =
            Hmac::<Sha256>::new_varkey(self.as_ref()).map_err(|_| PinError::InvalidKeyLen)?;
        mac.input(client_hash_data.as_ref());

        let mut out = [0u8; 16];
        out.copy_from_slice(&mac.result().code().as_slice()[0..16]);

        Ok(PinAuth(out))*/
    }
}

impl AsRef<[u8]> for PinToken {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Deserialize))]
pub struct PinAuth([u8; 16]);

impl AsRef<[u8]> for PinAuth {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for PinAuth {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(&self.0[..], serializer)
    }
}

pub struct Pin(String);

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Pin(redacted)")
    }
}

impl Pin {
    pub fn new(value: &str) -> Pin {
        Pin(String::from(value))
    }

    pub fn for_pin_token(&self) -> PinAuth {
        let mut hasher = Sha256::new();
        hasher.input(&self.0.as_bytes());

        let mut output = [0u8; 16];
        let len = output.len();
        output.copy_from_slice(&hasher.result().as_slice()[..len]);

        PinAuth(output)
    }
}

#[derive(Debug, Copy, Clone)]
pub enum PinError {
    PinIsTooShort,
    PinIsTooLong(usize),
    InvalidKeyLen,
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PinError::PinIsTooShort => write!(f, "PinError: pin is too short"),
            PinError::PinIsTooLong(len) => write!(f, "PinError: pin is too long ({})", len),
            PinError::InvalidKeyLen => write!(f, "PinError: invalid key len"),
        }
    }
}

impl StdErrorT for PinError {
    fn description(&self) -> &str {
        match *self {
            PinError::PinIsTooShort => "PinError: pin is too short",
            PinError::PinIsTooLong(_) => "PinError: pin is too long",
            PinError::InvalidKeyLen => "PinError: hmac invalid key len",
        }
    }
}
