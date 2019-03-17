use serde::ser::{Serialize, Serializer, SerializeMap};
use serde_cbor::error;
use serde_cbor::ser;
use serde_cbor::Value;
use serde_cbor::de::from_slice;

use super::attestation::AttestationObject;

use super::server::User;
use super::server::RelyingParty;
use super::server::PublicKeyCredentialParameters;
use super::server::PublicKeyCredentialDescriptor;

use super::transport::Device;

pub trait Ctap2Serialize {
    fn ctap2(&self) -> Result<Vec<u8>, error::Error>;
}

pub trait Request: Ctap2Serialize {
    type Reply;

    fn command() -> Command;

    fn wire_format(&self) -> Result<Vec<u8>, error::Error> {
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);

        buffer.push(Self::command() as u8);
        buffer.append(&mut self.ctap2()?);

        Ok(buffer)
    }

}
// Spec: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticator-api
#[repr(u8)]
pub enum Command {
    MakeCredentials = 0x01,
    GetAssertion = 0x02,
    GetInfo = 0x04,
    ClientPin = 0x06,
    Reset = 0x07,
    GetNextAssertion = 0x08,
}

#[derive(Debug)]
pub enum StatusCode {
    /// Indicates successful response.
    OK,
    /// Invalid/unexpected CBOR error.
    CBORUnexpectedType,
    /// Error when parsing CBOR.
    InvalidCBOR,
    /// Missing non-optional parameter.
    MissingParameter,
    /// Limit for number of items exceeded.
    LimitExceeded,
    /// Unsupported extension.
    UnsupportedExtension,
    /// Valid credential found in the exclude list.
    CredentialExcluded,
    /// Processing (Lengthy operation is in progress).
    Processing,
    /// Credential not valid for the authenticator.
    InvalidCredential,
    /// Authentication is waiting for user interaction.
    UserActionPending,
    /// Processing, lengthy operation is in progress.
    OperationPending,
    /// No request is pending.
    NoOperations,
    /// Authenticator does not support requested algorithm.
    UnsupportedAlgorithm,
    /// Not authorized for requested operation.
    OperationDenied,
    /// Internal key storage is full.
    KeyStoreFull,
    /// No outstanding operations.
    NoOperationPending,
    /// Unsupported option.
    UnsupportedOption,
    /// Not a valid option for current operation.
    InvalidOption,
    /// Pending keep alive was cancelled.
    KeepaliveCancel,
    /// No valid credentials provided.
    NoCredentials,
    /// Timeout waiting for user interaction.
    UserActionTimeout,
    /// Continuation command, such as, authenticatorGetNextAssertion not
    /// allowed.
    NotAllowed,
    /// PIN Invalid.
    PinInvalid,
    /// PIN Blocked.
    PinBlocked,
    /// PIN authentication,pinAuth, verification failed.
    PinAuthInvalid,
    /// PIN authentication,pinAuth, blocked. Requires power recycle to reset.
    PinAuthBlocked,
    /// No PIN has been set.
    PinNotSet,
    /// PIN is required for the selected operation.
    PinRequired,
    /// PIN policy violation. Currently only enforces minimum length.
    PinPolicyViolation,
    /// pinToken expired on authenticator.
    PinTokenExpired,
    /// Authenticator cannot handle this request due to memory constraints.
    RequestTooLarge,
    /// The current operation has timed out.
    ActionTimeout,
    /// User presence is required for the requested operation.
    UpRequired,

    /// Unknown status.
    Unknown(u8),
}

impl StatusCode {
    fn is_ok(&self) -> bool {
        match *self {
            StatusCode::OK => true,
            _ => false
        }
    }
}

impl From<u8> for StatusCode {
    fn from(value: u8) -> StatusCode {
        match value {
            0x00 => StatusCode::OK,
            0x11 => StatusCode::CBORUnexpectedType,
            0x12 => StatusCode::InvalidCBOR,
            0x14 => StatusCode::MissingParameter,
            0x15 => StatusCode::LimitExceeded,
            0x16 => StatusCode::UnsupportedExtension,
            0x19 => StatusCode::CredentialExcluded,
            0x21 => StatusCode::Processing,
            0x22 => StatusCode::InvalidCredential,
            0x23 => StatusCode::UserActionPending,
            0x24 => StatusCode::OperationPending,
            0x25 => StatusCode::NoOperations,
            0x26 => StatusCode::UnsupportedAlgorithm,
            0x27 => StatusCode::OperationDenied,
            0x28 => StatusCode::KeyStoreFull,
            0x2A => StatusCode::NoOperationPending,
            0x2B => StatusCode::UnsupportedOption,
            0x2C => StatusCode::InvalidOption,
            0x2D => StatusCode::KeepaliveCancel,
            0x2E => StatusCode::NoCredentials,
            0x2f => StatusCode::UserActionTimeout,
            0x30 => StatusCode::NotAllowed,
            0x31 => StatusCode::PinInvalid,
            0x32 => StatusCode::PinBlocked,
            0x33 => StatusCode::PinAuthInvalid,
            0x34 => StatusCode::PinAuthBlocked,
            0x35 => StatusCode::PinNotSet,
            0x36 => StatusCode::PinRequired,
            0x37 => StatusCode::PinPolicyViolation,
            0x38 => StatusCode::PinTokenExpired,
            0x39 => StatusCode::RequestTooLarge,
            0x3A => StatusCode::ActionTimeout,
            0x3B => StatusCode::UpRequired,

            othr => StatusCode::Unknown(othr),
        }
    }

}


/// First 16 bytes of HMAC-SHA-256 of clientDataHash using pinToken which
/// platform got from the authenticator: HMAC-SHA-256(pinToken, clientDataHash).
#[derive(Debug, Serialize)]
pub struct PinAuth([u8; 16]);

/// SHA256 of the client data
#[derive(Debug, Serialize)]
pub struct ClientDataHash([u8; 32]);

#[derive(Debug, Serialize)]
pub struct MakeCredentialsOptions {
    #[serde(rename="rk")]
    resident_key: bool,
    #[serde(rename="uv")]
    user_validation: bool,
}

#[derive(Debug)]
pub struct MakeCredentials {
    client_data_hash: ClientDataHash,
    rp: RelyingParty,
    user: User,
    pub_cred_params: PublicKeyCredentialParameters,
    exclude_list: Vec<PublicKeyCredentialDescriptor>,
    extensions: Value,
    options: Option<MakeCredentialsOptions>,
    pin_auth: Option<PinAuth>,
    pin_protocol: Option<u8>,
}

impl Ctap2Serialize for MakeCredentials {
    fn ctap2(&self) -> Result<Vec<u8>, error::Error> {
        ser::to_vec(&self)
    }
}

impl Serialize for MakeCredentials {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(9))?;
        map.serialize_entry(&1, &self.client_data_hash)?;
        map.serialize_entry(&2, &self.rp)?;
        map.serialize_entry(&3, &self.user)?;
        map.serialize_entry(&4, &self.pub_cred_params)?;
        if !self.exclude_list.is_empty() {
            map.serialize_entry(&5, &self.exclude_list)?;
        }
        map.serialize_entry(&6, &self.extensions)?;
        if self.options.is_some() {
            map.serialize_entry(&7, &self.options)?;
        }
        if self.pin_auth.is_some() {
            map.serialize_entry(&8, &self.pin_auth)?;
        }
        if self.pin_protocol.is_some() {
            map.serialize_entry(&9, &self.pin_protocol)?;
        }
        map.end()
    }
}


impl Request for MakeCredentials {
    type Reply = MakeCredentialsResponse;

    fn command() -> Command {
        Command::MakeCredentials
    }
}

#[derive(Debug)]
pub enum Error {
    InputTooSmall,
    Parsing(error::Error),
    StatusCode(StatusCode, Option<Value>)
}

pub trait Reply {
    type Output;
    fn parse(input: &[u8]) -> Result<Self::Output, Error>;
}

pub struct MakeCredentialsResponse;

impl Reply for MakeCredentialsResponse {
    type Output = AttestationObject;

    fn parse(input: &[u8]) -> Result<Self::Output, Error> {
        if input.len() < 1 {
            return Err(Error::InputTooSmall);
        }

        let status: StatusCode = input[0].into();
        if input.len() > 1 {
            if status.is_ok() {
                Ok(from_slice(&input[1..]).map_err(Error::Parsing)?)
            } else {
                let data: Value = from_slice(&input[1..]).map_err(Error::Parsing)?;
                Err(Error::StatusCode(status, Some(data)))
            }
        } else {
            Err(Error::InputTooSmall)
        }
    }
}


#[cfg(test)]
mod test {
    use super::{Reply, MakeCredentialsResponse};

    const MAKE_CREDENTIALS_SAMPLE_RESPONSE: [u8; 666] = [
        0x00,                                                                                                  // status = success
        0xa3,                                                                                                  // map(3)
           0x01,                                                                                               // unsigned(1)
           0x66,                                                                                               // text(6)
              0x70, 0x61, 0x63, 0x6b, 0x65, 0x64,                                                              // "packed"
           0x02,                                                                                               // unsigned(2)
           0x58, 0x9a,                                                                                         // bytes(154)
              0xc2, 0x89, 0xc5, 0xca, 0x9b, 0x04, 0x60, 0xf9, 0x34, 0x6a, 0xb4, 0xe4, 0x2d, 0x84, 0x27, 0x43,  // authData
              0x40, 0x4d, 0x31, 0xf4, 0x84, 0x68, 0x25, 0xa6, 0xd0, 0x65, 0xbe, 0x59, 0x7a, 0x87, 0x05, 0x1d,  // ...
              0x41, 0x00, 0x00, 0x00, 0x0b, 0xf8, 0xa0, 0x11, 0xf3, 0x8c, 0x0a, 0x4d, 0x15, 0x80, 0x06, 0x17,  // ...
              0x11, 0x1f, 0x9e, 0xdc, 0x7d, 0x00, 0x10, 0x89, 0x59, 0xce, 0xad, 0x5b, 0x5c, 0x48, 0x16, 0x4e,  // ...
              0x8a, 0xbc, 0xd6, 0xd9, 0x43, 0x5c, 0x6f, 0xa3, 0x63, 0x61, 0x6c, 0x67, 0x65, 0x45, 0x53, 0x32,  // ...
              0x35, 0x36, 0x61, 0x78, 0x58, 0x20, 0xf7, 0xc4, 0xf4, 0xa6, 0xf1, 0xd7, 0x95, 0x38, 0xdf, 0xa4,  // ...
              0xc9, 0xac, 0x50, 0x84, 0x8d, 0xf7, 0x08, 0xbc, 0x1c, 0x99, 0xf5, 0xe6, 0x0e, 0x51, 0xb4, 0x2a,  // ...
              0x52, 0x1b, 0x35, 0xd3, 0xb6, 0x9a, 0x61, 0x79, 0x58, 0x20, 0xde, 0x7b, 0x7d, 0x6c, 0xa5, 0x64,  // ...
              0xe7, 0x0e, 0xa3, 0x21, 0xa4, 0xd5, 0xd9, 0x6e, 0xa0, 0x0e, 0xf0, 0xe2, 0xdb, 0x89, 0xdd, 0x61,  // ...
              0xd4, 0x89, 0x4c, 0x15, 0xac, 0x58, 0x5b, 0xd2, 0x36, 0x84,                                      // ...
           0x03,                                                                                               // unsigned(3)
           0xa3,                                                                                               // map(3)
              0x63,                                                                                            // text(3)
                 0x61,  0x6c, 0x67,                                                                            // "alg"
              0x26,                                                                                            // -7 (ES256)
              0x63,                                                                                            // text(3)
                 0x73, 0x69, 0x67,                                                                             // "sig"
              0x58, 0x47,                                                                                      // bytes(71)
                 0x30, 0x45, 0x02, 0x20, 0x13, 0xf7, 0x3c, 0x5d, 0x9d, 0x53, 0x0e, 0x8c, 0xc1, 0x5c, 0xc9,     // signature...
                 0xbd, 0x96, 0xad, 0x58, 0x6d, 0x39, 0x36, 0x64, 0xe4, 0x62, 0xd5, 0xf0, 0x56, 0x12, 0x35,     // ...
                 0xe6, 0x35, 0x0f, 0x2b, 0x72, 0x89, 0x02, 0x21, 0x00, 0x90, 0x35, 0x7f, 0xf9, 0x10, 0xcc,     // ...
                 0xb5, 0x6a, 0xc5, 0xb5, 0x96, 0x51, 0x19, 0x48, 0x58, 0x1c, 0x8f, 0xdd, 0xb4, 0xa2, 0xb7,     // ...
                 0x99, 0x59, 0x94, 0x80, 0x78, 0xb0, 0x9f, 0x4b, 0xdc, 0x62, 0x29,                             // ...
              0x63,                                                                                            // text(3)
                 0x78, 0x35, 0x63,                                                                             // "x5c"
              0x81,                                                                                            // array(1)
                 0x59, 0x01, 0x97,                                                                             // bytes(407)
                    0x30, 0x82, 0x01, 0x93, 0x30, 0x82, 0x01, 0x38, 0xa0, 0x03, 0x02, 0x01, 0x02,              // certificate...
                    0x02, 0x09, 0x00, 0x85, 0x9b, 0x72, 0x6c, 0xb2, 0x4b, 0x4c, 0x29, 0x30, 0x0a,              // ...
                    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x47, 0x31,              // ...
                    0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,              // ...
                    0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x59, 0x75, 0x62,              // ...
                    0x69, 0x63, 0x6f, 0x20, 0x54, 0x65, 0x73, 0x74, 0x31, 0x22, 0x30, 0x20, 0x06,              // ...
                    0x03, 0x55, 0x04, 0x0b, 0x0c, 0x19, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,              // ...
                    0x69, 0x63, 0x61, 0x74, 0x6f, 0x72, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74,              // ...
                    0x61, 0x74, 0x69, 0x6f, 0x6e, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x31, 0x32,              // ...
                    0x30, 0x34, 0x31, 0x31, 0x35, 0x35, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x36,              // ...
                    0x31, 0x32, 0x30, 0x32, 0x31, 0x31, 0x35, 0x35, 0x30, 0x30, 0x5a, 0x30, 0x47,              // ...
                    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,              // ...
                    0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x59, 0x75,              // ...
                    0x62, 0x69, 0x63, 0x6f, 0x20, 0x54, 0x65, 0x73, 0x74, 0x31, 0x22, 0x30, 0x20,              // ...
                    0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x19, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e,              // ...
                    0x74, 0x69, 0x63, 0x61, 0x74, 0x6f, 0x72, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73,              // ...
                    0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,              // ...
                    0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,              // ...
                    0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xad, 0x11, 0xeb, 0x0e, 0x88, 0x52,              // ...
                    0xe5, 0x3a, 0xd5, 0xdf, 0xed, 0x86, 0xb4, 0x1e, 0x61, 0x34, 0xa1, 0x8e, 0xc4,              // ...
                    0xe1, 0xaf, 0x8f, 0x22, 0x1a, 0x3c, 0x7d, 0x6e, 0x63, 0x6c, 0x80, 0xea, 0x13,              // ...
                    0xc3, 0xd5, 0x04, 0xff, 0x2e, 0x76, 0x21, 0x1b, 0xb4, 0x45, 0x25, 0xb1, 0x96,              // ...
                    0xc4, 0x4c, 0xb4, 0x84, 0x99, 0x79, 0xcf, 0x6f, 0x89, 0x6e, 0xcd, 0x2b, 0xb8,              // ...
                    0x60, 0xde, 0x1b, 0xf4, 0x37, 0x6b, 0xa3, 0x0d, 0x30, 0x0b, 0x30, 0x09, 0x06,              // ...
                    0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2a,              // ...
                    0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02,              // ...
                    0x21, 0x00, 0xe9, 0xa3, 0x9f, 0x1b, 0x03, 0x19, 0x75, 0x25, 0xf7, 0x37, 0x3e,              // ...
                    0x10, 0xce, 0x77, 0xe7, 0x80, 0x21, 0x73, 0x1b, 0x94, 0xd0, 0xc0, 0x3f, 0x3f,              // ...
                    0xda, 0x1f, 0xd2, 0x2d, 0xb3, 0xd0, 0x30, 0xe7, 0x02, 0x21, 0x00, 0xc4, 0xfa,              // ...
                    0xec, 0x34, 0x45, 0xa8, 0x20, 0xcf, 0x43, 0x12, 0x9c, 0xdb, 0x00, 0xaa, 0xbe,              // ...
                    0xfd, 0x9a, 0xe2, 0xd8, 0x74, 0xf9, 0xc5, 0xd3, 0x43, 0xcb, 0x2f, 0x11, 0x3d,              // ...
                    0xa2, 0x37, 0x23, 0xf3,                                                                    // ...
    ];

    #[test]
    fn parse_response() {
        let reply = MakeCredentialsResponse::parse(&MAKE_CREDENTIALS_SAMPLE_RESPONSE[..]);

        assert!(reply.is_ok());
        let reply = reply.unwrap();

        assert_eq!(&reply.auth_data.rp_id_hash.0, &[0xc2, 0x89, 0xc5, 0xca, 0x9b, 0x04, 0x60, 0xf9, 0x34,
                                                    0x6a, 0xb4, 0xe4, 0x2d, 0x84, 0x27, 0x43, 0x40, 0x4d,
                                                    0x31, 0xf4, 0x84, 0x68, 0x25, 0xa6, 0xd0, 0x65, 0xbe,
                                                    0x59, 0x7a, 0x87, 0x5, 0x1d]);
    }
}

