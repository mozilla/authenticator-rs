use super::{Command, CommandError, RequestCtap1, RequestCtap2, Retryable, StatusCode};
use crate::consts::{
    PARAMETER_SIZE, U2F_AUTHENTICATE, U2F_CHECK_IS_REGISTERED, U2F_REQUEST_USER_PRESENCE,
};
use crate::ctap2::attestation::{AuthenticatorData, AuthenticatorDataFlags};
use crate::ctap2::client_data::CollectedClientData;
use crate::ctap2::commands::client_pin::PinAuth;
use crate::ctap2::commands::get_next_assertion::GetNextAssertion;
use crate::ctap2::commands::make_credentials::UserValidation;
use crate::ctap2::server::{PublicKeyCredentialDescriptor, RelyingParty, User};
use crate::transport::errors::{ApduErrorStatus, HIDError};
use crate::transport::FidoDevice;
use crate::u2ftypes::{U2FAPDUHeader, U2FDevice};
use nom::{
    do_parse, named,
    number::complete::{be_u32, be_u8},
};
use serde::{
    de::{Error as DesError, MapAccess, Visitor},
    ser::{Error as SerError, SerializeMap},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_bytes::ByteBuf;
use serde_cbor::{de::from_slice, ser, Value};
use serde_json::{value as json_value, Map};
use std::fmt;
use std::io;

#[derive(Copy, Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
pub struct GetAssertionOptions {
    #[serde(rename = "uv", skip_serializing_if = "Option::is_none")]
    pub user_validation: Option<bool>,
    #[serde(rename = "up", skip_serializing_if = "Option::is_none")]
    pub user_presence: Option<bool>,
}

impl Default for GetAssertionOptions {
    fn default() -> Self {
        Self {
            user_presence: None,
            user_validation: Some(true),
        }
    }
}

impl GetAssertionOptions {
    pub(crate) fn has_some(&self) -> bool {
        self.user_presence.is_some() || self.user_validation.is_some()
    }
}

impl UserValidation for GetAssertionOptions {
    fn ask_user_validation(&self) -> bool {
        if let Some(e) = self.user_validation {
            e
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct GetAssertion {
    client_data: CollectedClientData,
    rp: RelyingParty,
    allow_list: Vec<PublicKeyCredentialDescriptor>,

    // https://www.w3.org/TR/webauthn/#client-extension-input
    // The client extension input, which is a value that can be encoded in JSON,
    // is passed from the WebAuthn Relying Party to the client in the get() or
    // create() call, while the CBOR authenticator extension input is passed
    // from the client to the authenticator for authenticator extensions during
    // the processing of these calls.
    extensions: Map<String, json_value::Value>,
    options: GetAssertionOptions,

    pin_auth: Option<PinAuth>,
    //TODO(MS): pinProtocol
}

impl GetAssertion {
    pub fn new(
        client_data: CollectedClientData,
        rp: RelyingParty,
        allow_list: Vec<PublicKeyCredentialDescriptor>,
        options: GetAssertionOptions,
        pin_auth: Option<PinAuth>,
    ) -> Self {
        Self {
            client_data,
            rp,
            allow_list,
            // TODO(baloo): need to sort those out once final api is in
            extensions: Map::new(),
            options,
            pin_auth,
        }
    }
}

impl Serialize for GetAssertion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Need to define how many elements are going to be in the map
        // beforehand
        let mut map_len = 2;
        if !self.allow_list.is_empty() {
            map_len += 1;
        }
        if !self.extensions.is_empty() {
            map_len += 1;
        }
        if self.options.has_some() {
            map_len += 1;
        }
        if self.pin_auth.is_some() {
            map_len += 2;
        }

        let mut map = serializer.serialize_map(Some(map_len))?;
        map.serialize_entry(&1, &self.rp)?;

        let client_data_hash = self
            .client_data
            .hash()
            .map_err(|e| S::Error::custom(format!("error while hashing client data: {}", e)))?;
        map.serialize_entry(&2, &client_data_hash)?;
        if !self.allow_list.is_empty() {
            map.serialize_entry(&3, &self.allow_list)?;
        }
        if !self.extensions.is_empty() {
            map.serialize_entry(&4, &self.extensions)?;
        }
        if self.options.has_some() {
            map.serialize_entry(&5, &self.options)?;
        }
        if let Some(pin_auth) = &self.pin_auth {
            map.serialize_entry(&6, &pin_auth)?;
            map.serialize_entry(&7, &1)?;
        }
        map.end()
    }
}

impl RequestCtap1 for GetAssertion {
    type Output = AssertionObject;

    fn apdu_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, HIDError>
    where
        Dev: io::Read + io::Write + fmt::Debug + FidoDevice,
    {
        /// This command is used to check which key_handle is valid for this
        /// token this is sent before a GetAssertion command, to determine which
        /// is valid for a specific token and which key_handle GetAssertion
        /// should send to the token.
        #[derive(Debug)]
        struct GetAssertionCheck<'assertion> {
            key_handle: &'assertion [u8],
            client_data: &'assertion CollectedClientData,
            rp: &'assertion RelyingParty,
        }

        impl<'assertion> RequestCtap1 for GetAssertionCheck<'assertion> {
            type Output = ();

            fn apdu_format<Dev>(&self, _dev: &mut Dev) -> Result<Vec<u8>, HIDError>
            where
                Dev: U2FDevice + io::Read + io::Write + fmt::Debug,
            {
                let flags = U2F_CHECK_IS_REGISTERED;
                // TODO(MS): Need to check "up" here. If up==false, set to 0x08? Or not? Spec is ambiguous
                let mut auth_data =
                    Vec::with_capacity(2 * PARAMETER_SIZE + 1 + self.key_handle.len());

                auth_data.extend_from_slice(
                    self.client_data
                        .hash()
                        .map_err(|e| HIDError::Command(CommandError::Json(e)))?
                        .as_ref(),
                );
                auth_data.extend_from_slice(self.rp.hash().as_ref());
                auth_data.extend_from_slice(&[self.key_handle.len() as u8]);
                auth_data.extend_from_slice(self.key_handle);
                let cmd = U2F_AUTHENTICATE;
                let apdu = U2FAPDUHeader::serialize(cmd, flags, &auth_data)?;
                Ok(apdu)
            }

            fn handle_response_ctap1(
                &self,
                status: Result<(), ApduErrorStatus>,
                _input: &[u8],
            ) -> Result<Self::Output, Retryable<HIDError>> {
                match status {
                    Ok(_) | Err(ApduErrorStatus::ConditionsNotSatisfied) => Ok(()),
                    _ => Err(Retryable::Error(HIDError::DeviceError)),
                }
            }
        }

        let key_handle = self
            .allow_list
            .iter()
            .find_map(|allowed_handle| {
                let check_command = GetAssertionCheck {
                    key_handle: allowed_handle.id.as_ref(),
                    client_data: &self.client_data,
                    rp: &self.rp,
                };
                let res = dev.send_apdu(&check_command);
                match res {
                    Ok(_) => Some(allowed_handle.id.clone()),
                    _ => None,
                }
            })
            .ok_or(HIDError::DeviceNotSupported)?;

        debug!("sending key_handle = {:?}", key_handle);

        let flags = if self.options.user_presence.unwrap_or(false) {
            U2F_REQUEST_USER_PRESENCE
        } else {
            0
        };
        let mut auth_data =
            Vec::with_capacity(2 * PARAMETER_SIZE + 1 /* key_handle_len */ + key_handle.len());

        auth_data.extend_from_slice(
            self.client_data
                .hash()
                .map_err(|e| HIDError::Command(CommandError::Json(e)))?
                .as_ref(),
        );
        auth_data.extend_from_slice(self.rp.hash().as_ref());
        auth_data.extend_from_slice(&[key_handle.len() as u8]);
        auth_data.extend_from_slice(key_handle.as_ref());

        let cmd = U2F_AUTHENTICATE;
        let apdu = U2FAPDUHeader::serialize(cmd, flags, &auth_data)?;
        Ok(apdu)
    }

    fn handle_response_ctap1(
        &self,
        status: Result<(), ApduErrorStatus>,
        input: &[u8],
    ) -> Result<Self::Output, Retryable<HIDError>> {
        if Err(ApduErrorStatus::ConditionsNotSatisfied) == status {
            return Err(Retryable::Retry);
        }
        if status.is_err() {
            return Err(Retryable::Error(HIDError::DeviceError));
        }

        named!(
            parse_authentication<(u8, u32)>,
            do_parse!(user_presence: be_u8 >> counter: be_u32 >> (user_presence, counter))
        );

        let (user_presence, counter, signature) = match parse_authentication(input) {
            Ok((input, (user_presence, counter))) => {
                let signature = Vec::from(input);
                Ok((user_presence, counter, signature))
            }
            Err(e) => {
                error!("error while parsing authentication: {:?}", e);
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "unable to parse authentication",
                ))
                .map_err(|e| HIDError::IO(None, e))
                .map_err(Retryable::Error)
            }
        }?;

        let mut flags = AuthenticatorDataFlags::empty();
        if user_presence == 1 {
            flags |= AuthenticatorDataFlags::USER_PRESENT;
        }
        let auth_data = AuthenticatorData {
            rp_id_hash: self.rp.hash(),
            flags,
            counter,
            credential_data: None,
            extensions: Vec::new(),
        };
        let assertion = Assertion {
            credentials: None,
            signature,
            public_key: None,
            auth_data,
        };

        Ok(AssertionObject(vec![assertion]))
    }
}

impl RequestCtap2 for GetAssertion {
    type Output = AssertionObject;

    fn command() -> Command {
        Command::GetAssertion
    }

    fn wire_format<Dev>(&self, _dev: &mut Dev) -> Result<Vec<u8>, HIDError>
    where
        Dev: FidoDevice + io::Read + io::Write + fmt::Debug,
    {
        // TODO(MS): Add GetInfo-request here and others (See CommandDevice::new)
        Ok(ser::to_vec(&self).map_err(CommandError::Serialization)?)
    }

    fn handle_response_ctap2<Dev>(
        &self,
        dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, HIDError>
    where
        Dev: FidoDevice + io::Read + io::Write + fmt::Debug,
    {
        if input.is_empty() {
            return Err(CommandError::InputTooSmall).map_err(HIDError::Command);
        }

        let status: StatusCode = input[0].into();
        debug!("response status code: {:?}", status);
        if input.len() > 1 {
            if status.is_ok() {
                let assertion: GetAssertionResponse =
                    from_slice(&input[1..]).map_err(CommandError::Parsing)?;
                let number_of_credentials = assertion.number_of_credentials.unwrap_or(1);
                let mut assertions = Vec::with_capacity(number_of_credentials);
                assertions.push(assertion.into());

                let msg = GetNextAssertion;
                for _ in (1..number_of_credentials).rev() {
                    let new_cred = dev.send_cbor(&msg)?;
                    assertions.push(new_cred.into());
                }

                Ok(AssertionObject(assertions))
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

#[derive(Debug, PartialEq)]
pub struct Assertion {
    credentials: Option<serde_cbor::Value>,
    auth_data: AuthenticatorData,
    signature: Vec<u8>,
    public_key: Option<User>,
}

impl From<GetAssertionResponse> for Assertion {
    fn from(r: GetAssertionResponse) -> Self {
        Assertion {
            credentials: r.credentials,
            auth_data: r.auth_data,
            signature: r.signature,
            public_key: r.public_key,
        }
    }
}

// TODO(baloo): Move this to src/ctap2/mod.rs?
#[derive(Debug, PartialEq)]
pub struct AssertionObject(Vec<Assertion>);

impl AssertionObject {
    pub fn u2f_sign_data(&self) -> Vec<u8> {
        if let Some(first) = self.0.first() {
            first.signature.clone()
        } else {
            Vec::new()
        }
    }
}

pub(crate) struct GetAssertionResponse {
    credentials: Option<serde_cbor::Value>,
    auth_data: AuthenticatorData,
    signature: Vec<u8>,
    public_key: Option<User>,
    number_of_credentials: Option<usize>,
}

impl<'de> Deserialize<'de> for GetAssertionResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct GetAssertionResponseVisitor;

        impl<'de> Visitor<'de> for GetAssertionResponseVisitor {
            type Value = GetAssertionResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut credentials = None;
                let mut auth_data = None;
                let mut signature = None;
                let mut public_key = None;
                let mut number_of_credentials = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        1 => {
                            if credentials.is_some() {
                                return Err(M::Error::duplicate_field("credentials"));
                            }
                            credentials = Some(map.next_value()?);
                        }
                        2 => {
                            if auth_data.is_some() {
                                return Err(M::Error::duplicate_field("auth_data"));
                            }
                            auth_data = Some(map.next_value()?);
                        }
                        3 => {
                            if signature.is_some() {
                                return Err(M::Error::duplicate_field("signature"));
                            }
                            let signature_bytes: ByteBuf = map.next_value()?;
                            let signature_bytes: Vec<u8> = signature_bytes.into_vec();
                            signature = Some(signature_bytes);
                        }
                        4 => {
                            if public_key.is_some() {
                                return Err(M::Error::duplicate_field("public_key"));
                            }
                            public_key = map.next_value()?;
                        }
                        5 => {
                            if number_of_credentials.is_some() {
                                return Err(M::Error::duplicate_field("number_of_credentials"));
                            }
                            number_of_credentials = Some(map.next_value()?);
                        }
                        k => return Err(M::Error::custom(format!("unexpected key: {:?}", k))),
                    }
                }

                let auth_data = auth_data.ok_or_else(|| M::Error::missing_field("auth_data"))?;
                let signature = signature.ok_or_else(|| M::Error::missing_field("signature"))?;

                Ok(GetAssertionResponse {
                    credentials,
                    auth_data,
                    signature,
                    public_key,
                    number_of_credentials,
                })
            }
        }

        deserializer.deserialize_bytes(GetAssertionResponseVisitor)
    }
}

#[cfg(test)]
pub mod test {
    use super::{Assertion, GetAssertion, GetAssertionOptions};
    use crate::consts::{
        HIDCmd, SW_CONDITIONS_NOT_SATISFIED, SW_NO_ERROR, U2F_CHECK_IS_REGISTERED,
        U2F_REQUEST_USER_PRESENCE,
    };
    use crate::ctap2::attestation::{AuthenticatorData, AuthenticatorDataFlags};
    use crate::ctap2::client_data::{Challenge, CollectedClientData, TokenBinding, WebauthnType};
    use crate::ctap2::commands::get_assertion::AssertionObject;
    use crate::ctap2::commands::RequestCtap1;
    use crate::ctap2::server::{PublicKeyCredentialDescriptor, RelyingParty, RpIdHash, Transport};
    use crate::transport::FidoDevice;
    use crate::u2fprotocol::tests::platform::TestDevice;
    use crate::u2ftypes::U2FDevice;
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_get_assertion_ctap2() {
        // TODO(MS) Get some example data
    }

    fn fill_device_ctap1(device: &mut TestDevice, cid: [u8; 4], flags: u8, answer_status: [u8; 2]) {
        // ctap2 request
        let mut msg = cid.to_vec();
        msg.extend(&[HIDCmd::Msg.into(), 0x00, 0x8A]); // cmd + bcnt
        msg.extend(&[0x00, 0x2]); // U2F_AUTHENTICATE
        msg.extend(&[flags]);
        msg.extend(&[0x00, 0x00, 0x00]);
        msg.extend(&[0x81]); // Data len - 7
        msg.extend(&CLIENT_DATA_HASH);
        msg.extend(&RELYING_PARTY_HASH[..18]);
        device.add_write(&msg, 0);

        // Continuation package
        let mut msg = cid.to_vec();
        msg.extend(vec![0x00]); // SEQ
        msg.extend(&RELYING_PARTY_HASH[18..]);
        msg.extend(&[KEY_HANDLE.len() as u8]);
        msg.extend(&KEY_HANDLE[..44]);
        device.add_write(&msg, 0);

        let mut msg = cid.to_vec();
        msg.extend(vec![0x01]); // SEQ
        msg.extend(&KEY_HANDLE[44..]);
        device.add_write(&msg, 0);

        // fido response
        let mut msg = cid.to_vec();
        msg.extend(&[HIDCmd::Msg.into(), 0x0, 0x4D]); // cmd + bcnt
        msg.extend(&GET_ASSERTION_SAMPLE_RESPONSE_CTAP1[0..57]);
        device.add_read(&msg, 0);

        let mut msg = cid.to_vec();
        msg.extend(&[0x0]); // SEQ
        msg.extend(&GET_ASSERTION_SAMPLE_RESPONSE_CTAP1[57..]);
        msg.extend(&answer_status);
        device.add_read(&msg, 0);
    }

    #[test]
    fn test_get_assertion_ctap1() {
        let assertion = GetAssertion::new(
            CollectedClientData {
                webauthn_type: WebauthnType::Create,
                challenge: Challenge::from(vec![0x00, 0x01, 0x02, 0x03]),
                origin: String::from("example.com"),
                cross_origin: None,
                token_binding: Some(TokenBinding::Present(vec![0x00, 0x01, 0x02, 0x03])),
            },
            RelyingParty {
                id: String::from("example.com"),
                name: Some(String::from("Acme")),
                icon: None,
            },
            vec![PublicKeyCredentialDescriptor {
                id: vec![
                    0x3E, 0xBD, 0x89, 0xBF, 0x77, 0xEC, 0x50, 0x97, 0x55, 0xEE, 0x9C, 0x26, 0x35,
                    0xEF, 0xAA, 0xAC, 0x7B, 0x2B, 0x9C, 0x5C, 0xEF, 0x17, 0x36, 0xC3, 0x71, 0x7D,
                    0xA4, 0x85, 0x34, 0xC8, 0xC6, 0xB6, 0x54, 0xD7, 0xFF, 0x94, 0x5F, 0x50, 0xB5,
                    0xCC, 0x4E, 0x78, 0x05, 0x5B, 0xDD, 0x39, 0x6B, 0x64, 0xF7, 0x8D, 0xA2, 0xC5,
                    0xF9, 0x62, 0x00, 0xCC, 0xD4, 0x15, 0xCD, 0x08, 0xFE, 0x42, 0x00, 0x38,
                ],
                transports: vec![Transport::USB],
            }],
            GetAssertionOptions {
                user_presence: Some(true),
                user_validation: None,
            },
            None,
        );
        let mut device = TestDevice::new(); // not really used (all functions ignore it)
                                            // channel id
        let mut cid = [0u8; 4];
        thread_rng().fill_bytes(&mut cid);

        device.set_cid(cid);

        // ctap2 request
        fill_device_ctap1(
            &mut device,
            cid,
            U2F_CHECK_IS_REGISTERED,
            SW_CONDITIONS_NOT_SATISFIED,
        );
        let ctap1_request = assertion.apdu_format(&mut device).unwrap();
        // Check if the request is going to be correct
        assert_eq!(ctap1_request, GET_ASSERTION_SAMPLE_REQUEST_CTAP1);

        // Now do it again, but parse the actual response
        fill_device_ctap1(
            &mut device,
            cid,
            U2F_CHECK_IS_REGISTERED,
            SW_CONDITIONS_NOT_SATISFIED,
        );
        fill_device_ctap1(&mut device, cid, U2F_REQUEST_USER_PRESENCE, SW_NO_ERROR);

        let response = device.send_apdu(&assertion).unwrap();

        // Check if response is correct
        let expected_auth_data = AuthenticatorData {
            rp_id_hash: RpIdHash(RELYING_PARTY_HASH),
            flags: AuthenticatorDataFlags::USER_PRESENT,
            counter: 0x3B,
            credential_data: None,
            extensions: Vec::new(),
        };

        let expected_assertion = Assertion {
            credentials: None,
            signature: vec![
                0x30, 0x44, 0x02, 0x20, 0x7B, 0xDE, 0x0A, 0x52, 0xAC, 0x1F, 0x4C, 0x8B, 0x27, 0xE0,
                0x03, 0xA3, 0x70, 0xCD, 0x66, 0xA4, 0xC7, 0x11, 0x8D, 0xD2, 0x2D, 0x54, 0x47, 0x83,
                0x5F, 0x45, 0xB9, 0x9C, 0x68, 0x42, 0x3F, 0xF7, 0x02, 0x20, 0x3C, 0x51, 0x7B, 0x47,
                0x87, 0x7F, 0x85, 0x78, 0x2D, 0xE1, 0x00, 0x86, 0xA7, 0x83, 0xD1, 0xE7, 0xDF, 0x4E,
                0x36, 0x39, 0xE7, 0x71, 0xF5, 0xF6, 0xAF, 0xA3, 0x5A, 0xAD, 0x53, 0x73, 0x85, 0x8E,
            ],
            public_key: None,
            auth_data: expected_auth_data,
        };

        let expected = AssertionObject(vec![expected_assertion]);

        assert_eq!(response, expected);
    }

    const CLIENT_DATA_HASH: [u8; 32] = [
        0xc1, 0xdd, 0x35, 0x5f, 0x3c, 0x81, 0x69, 0x23, 0xe0, 0x57, 0xca, 0x03, 0x8d, 0xba, 0xad,
        0xb8, 0x5f, 0x95, 0x55, 0xcf, 0xc7, 0x62, 0x9b, 0x9d, 0x53, 0x66, 0x97, 0x53, 0x80, 0xd7,
        0x69, 0x4f,
    ];

    const RELYING_PARTY_HASH: [u8; 32] = [
        0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80, 0x34, 0xE2,
        0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2, 0x12, 0x55, 0x86, 0xCE,
        0x19, 0x47,
    ];
    const KEY_HANDLE: [u8; 64] = [
        0x3E, 0xBD, 0x89, 0xBF, 0x77, 0xEC, 0x50, 0x97, 0x55, 0xEE, 0x9C, 0x26, 0x35, 0xEF, 0xAA,
        0xAC, 0x7B, 0x2B, 0x9C, 0x5C, 0xEF, 0x17, 0x36, 0xC3, 0x71, 0x7D, 0xA4, 0x85, 0x34, 0xC8,
        0xC6, 0xB6, 0x54, 0xD7, 0xFF, 0x94, 0x5F, 0x50, 0xB5, 0xCC, 0x4E, 0x78, 0x05, 0x5B, 0xDD,
        0x39, 0x6B, 0x64, 0xF7, 0x8D, 0xA2, 0xC5, 0xF9, 0x62, 0x00, 0xCC, 0xD4, 0x15, 0xCD, 0x08,
        0xFE, 0x42, 0x00, 0x38,
    ];

    const GET_ASSERTION_SAMPLE_REQUEST_CTAP1: [u8; 138] = [
        // CBOR Header
        0x0, // leading zero
        0x2, // CMD U2F_Authenticate
        0x3, // Flags (user presence)
        0x0, 0x0, // zero bits
        0x0, 0x81, // size
        // NOTE: This has been taken from CTAP2.0 spec, but the clientDataHash has been replaced
        //       to be able to operate with known values for CollectedClientData (spec doesn't say
        //       what values led to the provided example hash)
        // clientDataHash:
        0xc1, 0xdd, 0x35, 0x5f, 0x3c, 0x81, 0x69, 0x23, 0xe0, 0x57, 0xca, 0x03, 0x8d, // hash
        0xba, 0xad, 0xb8, 0x5f, 0x95, 0x55, 0xcf, 0xc7, 0x62, 0x9b, 0x9d, 0x53, 0x66, // hash
        0x97, 0x53, 0x80, 0xd7, 0x69, 0x4f, // hash
        // rpIdHash:
        0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80, 0x34, 0xE2,
        0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2, 0x12, 0x55, 0x86, 0xCE,
        0x19, 0x47, // ..
        // Key Handle Length (1 Byte):
        0x40, // ..
        // Key Handle (Key Handle Length Bytes):
        0x3E, 0xBD, 0x89, 0xBF, 0x77, 0xEC, 0x50, 0x97, 0x55, 0xEE, 0x9C, 0x26, 0x35, 0xEF, 0xAA,
        0xAC, 0x7B, 0x2B, 0x9C, 0x5C, 0xEF, 0x17, 0x36, 0xC3, 0x71, 0x7D, 0xA4, 0x85, 0x34, 0xC8,
        0xC6, 0xB6, 0x54, 0xD7, 0xFF, 0x94, 0x5F, 0x50, 0xB5, 0xCC, 0x4E, 0x78, 0x05, 0x5B, 0xDD,
        0x39, 0x6B, 0x64, 0xF7, 0x8D, 0xA2, 0xC5, 0xF9, 0x62, 0x00, 0xCC, 0xD4, 0x15, 0xCD, 0x08,
        0xFE, 0x42, 0x00, 0x38, 0x0, 0x0, // 2 trailing zeros from protocol
    ];

    const GET_ASSERTION_SAMPLE_RESPONSE_CTAP1: [u8; 75] = [
        0x01, // User Presence (1 Byte)
        0x00, 0x00, 0x00, 0x3B, // Sign Count (4 Bytes)
        // Signature (variable Length)
        0x30, 0x44, 0x02, 0x20, 0x7B, 0xDE, 0x0A, 0x52, 0xAC, 0x1F, 0x4C, 0x8B, 0x27, 0xE0, 0x03,
        0xA3, 0x70, 0xCD, 0x66, 0xA4, 0xC7, 0x11, 0x8D, 0xD2, 0x2D, 0x54, 0x47, 0x83, 0x5F, 0x45,
        0xB9, 0x9C, 0x68, 0x42, 0x3F, 0xF7, 0x02, 0x20, 0x3C, 0x51, 0x7B, 0x47, 0x87, 0x7F, 0x85,
        0x78, 0x2D, 0xE1, 0x00, 0x86, 0xA7, 0x83, 0xD1, 0xE7, 0xDF, 0x4E, 0x36, 0x39, 0xE7, 0x71,
        0xF5, 0xF6, 0xAF, 0xA3, 0x5A, 0xAD, 0x53, 0x73, 0x85, 0x8E,
    ];
}
