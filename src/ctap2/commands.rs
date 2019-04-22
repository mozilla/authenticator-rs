use std::default::Default;
use std::error::Error as StdErrorT;
use std::ffi::CString;
use std::fmt;
use std::io::{self, Read};

use pretty_hex::pretty_hex;

use cose::agreement::{self, Agreement};
use cose::{EllipticCurve, PublicKey};
use hmac::{Hmac, Mac};
use nom::{be_u32, be_u8};
use serde::de::{self, Deserialize, Deserializer, Error as SerdeError, MapAccess, Visitor};
use serde::ser::{Error as ErrorT, Serialize, SerializeMap, Serializer};
use serde_bytes::ByteBuf;
use serde_cbor::de::from_slice;
use serde_cbor::error;
use serde_cbor::ser::{self, to_vec};
use serde_cbor::Value;
use serde_json::value as json_value;
use serde_json::{self as json, Map};
use sha2::{Digest, Sha256};

use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};

use crate::transport::{self, ApduErrorStatus, Error as TransportError, FidoDevice};

use crate::ctap2::attestation::{
    AAGuid, AttestationObject, AttestationStatement, AttestationStatementFidoU2F,
    AttestedCredentialData, AuthenticatorData, AuthenticatorDataFlags,
};

use crate::ctap2::server::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, RelyingParty, User,
};

use crate::ctap::{ClientDataHash, CollectedClientData, Version};

use crate::consts::{
    PARAMETER_SIZE, U2F_AUTHENTICATE, U2F_CHECK_IS_REGISTERED, U2F_REGISTER,
    U2F_REQUEST_USER_PRESENCE, U2F_VERSION,
};
use crate::u2ftypes::U2FAPDUHeader;

pub(crate) trait Request<T>
where
    Self: fmt::Debug,
    Self: RequestCtap1<Output = T>,
    Self: RequestCtap2<Output = T>,
{
    fn maximum_version(&self) -> Version;
    fn minimum_version(&self) -> Version;
}

/// Retryable wraps an error type and may ask manager to retry sending a
/// command, this is useful for ctap1 where token will reply with "condition not
/// sufficient" because user needs to press the button.
pub(crate) enum Retryable<T> {
    Retry,
    Error(T),
}

impl<T> Retryable<T> {
    pub fn is_retry(&self) -> bool {
        match *self {
            Retryable::Retry => true,
            _ => false,
        }
    }

    pub fn is_error(&self) -> bool {
        !self.is_retry()
    }
}

impl<T> From<T> for Retryable<T> {
    fn from(e: T) -> Self {
        Retryable::Error(e)
    }
}

pub(crate) trait RequestCtap1: fmt::Debug {
    type Output;

    fn apdu_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, transport::Error>
    where
        Dev: FidoDevice;

    fn handle_response_ctap1(
        &self,
        status: Result<(), ApduErrorStatus>,
        input: &[u8],
    ) -> Result<Self::Output, Retryable<TransportError>>;
}

pub(crate) trait RequestCtap2: fmt::Debug {
    type Output;

    fn command() -> Command;

    fn wire_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, transport::Error>
    where
        Dev: FidoDevice;

    fn handle_response_ctap2<Dev>(
        &self,
        dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, TransportError>
    where
        Dev: FidoDevice;
}

trait RequestWithPin: RequestCtap2 {
    fn pin(&self) -> Option<&Pin>;
    fn client_data_hash(&self) -> Result<ClientDataHash, Error>;
}

// Spec: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticator-api
#[repr(u8)]
#[derive(Debug)]
pub enum Command {
    MakeCredentials = 0x01,
    GetAssertion = 0x02,
    GetInfo = 0x04,
    ClientPin = 0x06,
    Reset = 0x07,
    GetNextAssertion = 0x08,
}

impl Command {
    #[cfg(test)]
    pub fn from_u8(v: u8) -> Option<Command> {
        match v {
            0x01 => Some(Command::MakeCredentials),
            0x02 => Some(Command::GetAssertion),
            0x04 => Some(Command::GetInfo),
            0x06 => Some(Command::ClientPin),
            0x07 => Some(Command::Reset),
            0x08 => Some(Command::GetNextAssertion),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum StatusCode {
    /// Indicates successful response.
    OK,
    /// The command is not a valid CTAP command.
    InvalidCommand,
    /// The command included an invalid parameter.
    InvalidParameter,
    /// Invalid message or item length.
    InvalidLength,
    /// Invalid message sequencing.
    InvalidSeq,
    /// Message timed out.
    Timeout,
    /// Channel busy.
    ChannelBusy,
    /// Command requires channel lock.
    LockRequired,
    /// Command not allowed on this cid.
    InvalidChannel,
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
            _ => false,
        }
    }

    fn device_busy(&self) -> bool {
        match *self {
            StatusCode::ChannelBusy => true,
            _ => false,
        }
    }
}

impl From<u8> for StatusCode {
    fn from(value: u8) -> StatusCode {
        match value {
            0x00 => StatusCode::OK,
            0x01 => StatusCode::InvalidCommand,
            0x02 => StatusCode::InvalidParameter,
            0x03 => StatusCode::InvalidLength,
            0x04 => StatusCode::InvalidSeq,
            0x05 => StatusCode::Timeout,
            0x06 => StatusCode::ChannelBusy,
            0x0A => StatusCode::LockRequired,
            0x0B => StatusCode::InvalidChannel,
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

#[cfg(test)]
impl Into<u8> for StatusCode {
    fn into(self) -> u8 {
        match self {
            StatusCode::OK => 0x00,
            StatusCode::InvalidCommand => 0x01,
            StatusCode::InvalidParameter => 0x02,
            StatusCode::InvalidLength => 0x03,
            StatusCode::InvalidSeq => 0x04,
            StatusCode::Timeout => 0x05,
            StatusCode::ChannelBusy => 0x06,
            StatusCode::LockRequired => 0x0A,
            StatusCode::InvalidChannel => 0x0B,
            StatusCode::CBORUnexpectedType => 0x11,
            StatusCode::InvalidCBOR => 0x12,
            StatusCode::MissingParameter => 0x14,
            StatusCode::LimitExceeded => 0x15,
            StatusCode::UnsupportedExtension => 0x16,
            StatusCode::CredentialExcluded => 0x19,
            StatusCode::Processing => 0x21,
            StatusCode::InvalidCredential => 0x22,
            StatusCode::UserActionPending => 0x23,
            StatusCode::OperationPending => 0x24,
            StatusCode::NoOperations => 0x25,
            StatusCode::UnsupportedAlgorithm => 0x26,
            StatusCode::OperationDenied => 0x27,
            StatusCode::KeyStoreFull => 0x28,
            StatusCode::NoOperationPending => 0x2A,
            StatusCode::UnsupportedOption => 0x2B,
            StatusCode::InvalidOption => 0x2C,
            StatusCode::KeepaliveCancel => 0x2D,
            StatusCode::NoCredentials => 0x2E,
            StatusCode::UserActionTimeout => 0x2f,
            StatusCode::NotAllowed => 0x30,
            StatusCode::PinInvalid => 0x31,
            StatusCode::PinBlocked => 0x32,
            StatusCode::PinAuthInvalid => 0x33,
            StatusCode::PinAuthBlocked => 0x34,
            StatusCode::PinNotSet => 0x35,
            StatusCode::PinRequired => 0x36,
            StatusCode::PinPolicyViolation => 0x37,
            StatusCode::PinTokenExpired => 0x38,
            StatusCode::RequestTooLarge => 0x39,
            StatusCode::ActionTimeout => 0x3A,
            StatusCode::UpRequired => 0x3B,

            StatusCode::Unknown(othr) => othr,
        }
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

#[derive(Debug)]
#[cfg_attr(test, derive(Deserialize))]
pub struct PinAuth([u8; 16]);

impl AsRef<[u8]> for PinAuth {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Serialize for PinAuth {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(&self.0, serializer)
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
        hasher.input(&self.0.as_bytes()[..]);

        let mut output = [0u8; 16];
        let len = output.len();
        output.copy_from_slice(&hasher.result().as_slice()[..len]);

        PinAuth(output)
    }
}

/// Internal struct to serialize command that may need to serialize differently
/// depending on the device (pin_token, ...)
struct CommandDevice<'command, Command> {
    command: &'command Command,
    pin_auth: Option<PinAuth>,
}

impl<'command, Command> CommandDevice<'command, Command>
where
    Command: RequestWithPin,
{
    fn new<Dev>(dev: &mut Dev, command: &'command Command) -> Result<Self, transport::Error>
    where
        Dev: FidoDevice,
    {
        let info = if let Some(authenticator_info) = dev.authenticator_info().cloned() {
            authenticator_info
        } else {
            let info_command = GetInfo::default();
            let info = dev.send_cbor(&info_command)?;
            debug!("infos: {:?}", info);

            dev.set_authenticator_info(info.clone());
            info
        };

        let pin_auth = if info.client_pin_set() {
            let pin = if let Some(pin) = command.pin() {
                pin
            } else {
                return Err(Error::StatusCode(StatusCode::PinRequired, None).into());
            };

            let shared_secret = if let Some(shared_secret) = dev.shared_secret().cloned() {
                shared_secret
            } else {
                let pin_command = GetKeyAgreement::new(&info)?;
                let device_key_agreement = dev.send_cbor(&pin_command)?;
                let shared_secret = device_key_agreement.shared_secret()?;
                dev.set_shared_secret(shared_secret.clone());
                shared_secret
            };

            let pin_command = GetPinToken::new(&info, &shared_secret, &pin)?;
            let pin_token = dev.send_cbor(&pin_command)?;

            Some(
                pin_token
                    .auth(&command.client_data_hash()?)
                    .map_err(Error::Pin)?,
            )
        } else {
            None
        };

        Ok(Self { command, pin_auth })
    }
}

#[derive(Copy, Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
pub struct MakeCredentialsOptions {
    #[serde(rename = "rk")]
    pub resident_key: bool,
    #[serde(rename = "uv")]
    pub user_validation: bool,
}

impl Default for MakeCredentialsOptions {
    fn default() -> Self {
        Self {
            resident_key: false,
            user_validation: true,
        }
    }
}

trait UserValidation {
    fn ask_user_validation(&self) -> bool;
}

impl UserValidation for Option<MakeCredentialsOptions> {
    fn ask_user_validation(&self) -> bool {
        match *self {
            Some(ref e) if e.user_validation => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct MakeCredentials {
    client_data: CollectedClientData,
    rp: RelyingParty,
    // Note(baloo): If none -> ctap1
    user: Option<User>,
    pub_cred_params: Vec<PublicKeyCredentialParameters>,
    exclude_list: Vec<PublicKeyCredentialDescriptor>,

    // https://www.w3.org/TR/webauthn/#client-extension-input
    // The client extension input, which is a value that can be encoded in JSON,
    // is passed from the WebAuthn Relying Party to the client in the get() or
    // create() call, while the CBOR authenticator extension input is passed
    // from the client to the authenticator for authenticator extensions during
    // the processing of these calls.
    extensions: Map<String, json_value::Value>,
    options: Option<MakeCredentialsOptions>,
    pin: Option<Pin>,
}

impl MakeCredentials {
    pub fn new(
        client_data: CollectedClientData,
        rp: RelyingParty,
        user: Option<User>,
        pub_cred_params: Vec<PublicKeyCredentialParameters>,
        exclude_list: Vec<PublicKeyCredentialDescriptor>,
        options: Option<MakeCredentialsOptions>,
        pin: Option<Pin>,
    ) -> Self {
        Self {
            client_data,
            rp,
            user,
            pub_cred_params,
            exclude_list,
            // TODO(baloo): need to sort those out once final api is in
            extensions: Map::new(),
            options,
            pin,
        }
    }
}

impl<'command> Serialize for CommandDevice<'command, MakeCredentials> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let command = &self.command;
        let pin_auth = &self.pin_auth;

        // Need to define how many elements are going to be in the map
        // beforehand
        let mut map_len = 4;
        if !command.exclude_list.is_empty() {
            map_len += 1;
        }
        if !command.extensions.is_empty() {
            map_len += 1;
        }
        if command.options.is_some() {
            map_len += 1;
        }
        if pin_auth.is_some() {
            map_len += 2;
        }

        let mut map = serializer.serialize_map(Some(map_len))?;
        let client_data_hash = command
            .client_data
            .hash()
            .map_err(|e| S::Error::custom(format!("error while hashing client data: {}", e)))?;
        map.serialize_entry(&1, &client_data_hash)?;
        match command.rp {
            RelyingParty::Data(ref d) => {
                map.serialize_entry(&2, &d)?;
            }
            _ => {
                return Err(S::Error::custom(
                    "Can't serialize a RelyingParty::Hash for ctap2",
                ));
            }
        }
        map.serialize_entry(&3, &command.user)?;
        map.serialize_entry(&4, &command.pub_cred_params)?;
        if !command.exclude_list.is_empty() {
            map.serialize_entry(&5, &command.exclude_list)?;
        }
        if !command.extensions.is_empty() {
            map.serialize_entry(&6, &command.extensions)?;
        }
        if command.options.is_some() {
            map.serialize_entry(&7, &command.options)?;
        }
        if let Some(pin_auth) = pin_auth {
            map.serialize_entry(&8, &pin_auth)?;
            map.serialize_entry(&9, &1)?;
        }
        map.end()
    }
}

impl Request<(AttestationObject, CollectedClientData)> for MakeCredentials {
    fn maximum_version(&self) -> Version {
        if self.user.is_none() {
            return Version::CTAP1;
        }
        if self.client_data.origin.is_none() {
            return Version::CTAP1;
        }

        Version::CTAP2
    }

    fn minimum_version(&self) -> Version {
        if self.client_data.token_binding.is_some() {
            return Version::CTAP2;
        }

        Version::CTAP1
    }
}

impl RequestCtap1 for MakeCredentials {
    type Output = (AttestationObject, CollectedClientData);

    fn apdu_format<Dev>(&self, _dev: &mut Dev) -> Result<Vec<u8>, transport::Error>
    where
        Dev: FidoDevice,
    {
        let flags = if self.options.ask_user_validation() {
            U2F_REQUEST_USER_PRESENCE
        } else {
            0
        };

        let mut register_data = Vec::with_capacity(2 * PARAMETER_SIZE);
        register_data.extend_from_slice(self.client_data.challenge.as_ref());
        register_data.extend_from_slice(self.rp.hash().as_ref());

        let cmd = U2F_REGISTER;
        let apdu = U2FAPDUHeader::serialize(cmd, flags, &register_data)?;

        Ok(apdu)
    }

    fn handle_response_ctap1(
        &self,
        status: Result<(), ApduErrorStatus>,
        input: &[u8],
    ) -> Result<Self::Output, Retryable<TransportError>> {
        if Err(ApduErrorStatus::ConditionsNotSatisfied) == status {
            return Err(Retryable::Retry);
        }

        named!(
            parse_register<(&[u8], &[u8])>,
            do_parse!(
                reserved: tag!(&[0x05]) >>
                public_key: take!(65) >>
                key_handle_len: be_u8 >>
                key_handle: take!(key_handle_len) >>
                (public_key, key_handle)
            )
        );

        let (rest, (public_key, key_handle)) = parse_register(input)
            .map_err(|e| {
                error!("error while parsing registration = {:?}", e);
                io::Error::new(io::ErrorKind::Other, "unable to parse registration")
            })
            .map_err(|e| TransportError::IO(None, e))
            .map_err(Retryable::Error)?;

        let (signature, cert) = der_parser::parse_der(rest)
            .map_err(|e| {
                error!("error while parsing cert = {:?}", e);
                let err = io::Error::new(io::ErrorKind::Other, "Failed to parse x509 certificate");
                let err = error::Error::from(err);
                let err = Error::Parsing(err);
                let err = TransportError::Command(err);
                Retryable::Error(err)
            })
            .map(|(sig, cert)| (sig, &rest[..rest.len() - sig.len()]))?;

        let auth_data = AuthenticatorData {
            rp_id_hash: self.rp.hash(),
            flags: AuthenticatorDataFlags::empty(),
            counter: 0,
            credential_data: Some(AttestedCredentialData {
                aaguid: AAGuid::empty(),
                credential_id: Vec::from(&key_handle[..]),
                // TODO(baloo): this is wrong, this is not the format expected by cose::PublicKey
                // (or is it?)
                // see This is the (uncompressed) x,y-representation of a curve point on the P-256 NIST elliptic curve.
                // https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
                credential_public_key: PublicKey::new(
                    EllipticCurve::P256,
                    Vec::from(&public_key[..]),
                ),
            }),
            extensions: Vec::new(),
        };

        let att_statement_u2f = AttestationStatementFidoU2F::new(cert, signature);
        let att_statement = AttestationStatement::FidoU2F(att_statement_u2f);
        let attestation_object = AttestationObject {
            auth_data,
            att_statement,
        };
        let client_data = self.client_data.clone();

        Ok((attestation_object, client_data))
    }
}

impl RequestCtap2 for MakeCredentials {
    type Output = (AttestationObject, CollectedClientData);

    fn command() -> Command {
        Command::MakeCredentials
    }

    fn wire_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, transport::Error>
    where
        Dev: FidoDevice,
    {
        let cd = CommandDevice::new(dev, self)?;

        Ok(ser::to_vec(&cd).map_err(Error::Serialization)?)
    }

    fn handle_response_ctap2<Dev>(
        &self,
        _dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, TransportError>
    where
        Dev: FidoDevice,
    {
        if input.is_empty() {
            return Err(Error::InputTooSmall).map_err(TransportError::Command);
        }

        let status: StatusCode = input[0].into();
        debug!("response status code: {:?}", status);
        if input.len() > 1 {
            if status.is_ok() {
                let attestation = from_slice(&input[1..]).map_err(Error::Parsing)?;
                let client_data = self.client_data.clone();
                Ok((attestation, client_data))
            } else {
                let data: Value = from_slice(&input[1..]).map_err(Error::Parsing)?;
                Err(Error::StatusCode(status, Some(data))).map_err(TransportError::Command)
            }
        } else if status.is_ok() {
            Err(Error::InputTooSmall).map_err(TransportError::Command)
        } else {
            Err(Error::StatusCode(status, None)).map_err(TransportError::Command)
        }
    }
}

impl RequestWithPin for MakeCredentials {
    fn pin(&self) -> Option<&Pin> {
        self.pin.as_ref()
    }

    fn client_data_hash(&self) -> Result<ClientDataHash, Error> {
        self.client_data.hash().map_err(Error::Json)
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
    options: Option<MakeCredentialsOptions>,

    pin: Option<Pin>,
}

impl GetAssertion {
    pub fn new(
        client_data: CollectedClientData,
        rp: RelyingParty,
        allow_list: Vec<PublicKeyCredentialDescriptor>,
        options: Option<MakeCredentialsOptions>,
        pin: Option<Pin>,
    ) -> Self {
        Self {
            client_data,
            rp,
            allow_list,
            // TODO(baloo): need to sort those out once final api is in
            extensions: Map::new(),
            options,
            pin,
        }
    }
}

impl<'command> Serialize for CommandDevice<'command, GetAssertion> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let command = &self.command;
        let pin_auth = &self.pin_auth;

        // Need to define how many elements are going to be in the map
        // beforehand
        let mut map_len = 2;
        if !command.allow_list.is_empty() {
            map_len += 1;
        }
        if !command.extensions.is_empty() {
            map_len += 1;
        }
        if command.options.is_some() {
            map_len += 1;
        }
        if pin_auth.is_some() {
            map_len += 2;
        }

        let mut map = serializer.serialize_map(Some(map_len))?;
        match command.rp {
            RelyingParty::Data(ref d) => {
                map.serialize_entry(&1, &d)?;
            }
            _ => {
                return Err(S::Error::custom(
                    "Can't serialize a RelyingParty::Hash for ctap2",
                ));
            }
        }

        let client_data_hash = command
            .client_data
            .hash()
            .map_err(|e| S::Error::custom(format!("error while hashing client data: {}", e)))?;
        map.serialize_entry(&2, &client_data_hash)?;
        if !command.allow_list.is_empty() {
            map.serialize_entry(&3, &command.allow_list)?;
        }
        if !command.extensions.is_empty() {
            map.serialize_entry(&4, &command.extensions)?;
        }
        if command.options.is_some() {
            map.serialize_entry(&5, &command.options)?;
        }
        if let Some(pin_auth) = pin_auth {
            map.serialize_entry(&6, &pin_auth)?;
            map.serialize_entry(&7, &1)?;
        }
        map.end()
    }
}

impl Request<AssertionObject> for GetAssertion {
    fn maximum_version(&self) -> Version {
        if self.rp.is_hash() {
            return Version::CTAP1;
        }

        Version::CTAP2
    }

    fn minimum_version(&self) -> Version {
        Version::CTAP1
    }
}

impl RequestCtap1 for GetAssertion {
    type Output = AssertionObject;

    fn apdu_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, transport::Error>
    where
        Dev: FidoDevice,
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

            fn apdu_format<Dev>(&self, _dev: &mut Dev) -> Result<Vec<u8>, transport::Error>
            where
                Dev: FidoDevice,
            {
                let flags = U2F_CHECK_IS_REGISTERED;
                let mut auth_data = Vec::with_capacity(
                    2 * PARAMETER_SIZE + 1 /* key_handle_len */ + self.key_handle.len(),
                );

                auth_data.extend_from_slice(self.client_data.challenge.as_ref());
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
                input: &[u8],
            ) -> Result<Self::Output, Retryable<TransportError>> {
                match status {
                    Err(ref status) if status.is_conditions_not_satisfied() => Ok(()),
                    _ => Err(Retryable::Error(TransportError::DeviceError)),
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

                match dev.send_apdu(&check_command) {
                    Ok(_) => Some(allowed_handle.id.clone()),
                    _ => None,
                }
            })
            .ok_or(transport::Error::DeviceNotSupported)?;

        debug!("sending key_handle = {:?}", key_handle);

        let flags = if self.options.ask_user_validation() {
            U2F_REQUEST_USER_PRESENCE
        } else {
            0
        };
        let mut auth_data =
            Vec::with_capacity(2 * PARAMETER_SIZE + 1 /* key_handle_len */ + key_handle.len());

        auth_data.extend_from_slice(self.client_data.challenge.as_ref());
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
    ) -> Result<Self::Output, Retryable<TransportError>> {
        if Err(ApduErrorStatus::ConditionsNotSatisfied) == status {
            return Err(Retryable::Retry);
        }
        if status.is_err() {
            return Err(Retryable::Error(TransportError::DeviceError));
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
                .map_err(|e| TransportError::IO(None, e))
                .map_err(Retryable::Error)
            },
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

    fn wire_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, transport::Error>
    where
        Dev: FidoDevice,
    {
        let cd = CommandDevice::new(dev, self)?;

        Ok(ser::to_vec(&cd).map_err(Error::Serialization)?)
    }

    fn handle_response_ctap2<Dev>(
        &self,
        dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, TransportError>
    where
        Dev: FidoDevice,
    {
        if input.is_empty() {
            return Err(Error::InputTooSmall).map_err(TransportError::Command);
        }

        let status: StatusCode = input[0].into();
        debug!("response status code: {:?}", status);
        if input.len() > 1 {
            if status.is_ok() {
                let assertion: GetAssertionResponse =
                    from_slice(&input[1..]).map_err(Error::Parsing)?;
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
                let data: Value = from_slice(&input[1..]).map_err(Error::Parsing)?;
                Err(Error::StatusCode(status, Some(data))).map_err(TransportError::Command)
            }
        } else if status.is_ok() {
            Err(Error::InputTooSmall).map_err(TransportError::Command)
        } else {
            Err(Error::StatusCode(status, None)).map_err(TransportError::Command)
        }
    }
}

impl RequestWithPin for GetAssertion {
    fn pin(&self) -> Option<&Pin> {
        self.pin.as_ref()
    }

    fn client_data_hash(&self) -> Result<ClientDataHash, Error> {
        self.client_data.hash().map_err(Error::Json)
    }
}

#[derive(Debug)]
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
#[derive(Debug)]
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

struct GetAssertionResponse {
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
                                return Err(de::Error::duplicate_field("credentials"));
                            }
                            credentials = Some(map.next_value()?);
                        }
                        2 => {
                            if auth_data.is_some() {
                                return Err(de::Error::duplicate_field("auth_data"));
                            }
                            auth_data = Some(map.next_value()?);
                        }
                        3 => {
                            if signature.is_some() {
                                return Err(de::Error::duplicate_field("signature"));
                            }
                            let signature_bytes: ByteBuf = map.next_value()?;
                            let signature_bytes: Vec<u8> = signature_bytes.into();
                            signature = Some(signature_bytes);
                        }
                        4 => {
                            if public_key.is_some() {
                                return Err(de::Error::duplicate_field("public_key"));
                            }
                            public_key = map.next_value()?;
                        }
                        5 => {
                            if number_of_credentials.is_some() {
                                return Err(de::Error::duplicate_field("number_of_credentials"));
                            }
                            number_of_credentials = Some(map.next_value()?);
                        }
                        k => return Err(M::Error::custom(format!("unexpected key: {:?}", k))),
                    }
                }

                let auth_data = auth_data.ok_or(de::Error::missing_field("auth_data"))?;
                let signature = signature.ok_or(de::Error::missing_field("signature"))?;

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

#[derive(Debug)]
struct GetNextAssertion;

impl RequestCtap2 for GetNextAssertion {
    type Output = GetAssertionResponse;

    fn command() -> Command {
        Command::GetNextAssertion
    }

    fn wire_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, transport::Error>
    where
        Dev: FidoDevice,
    {
        Ok(Vec::new())
    }

    fn handle_response_ctap2<Dev>(
        &self,
        _dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, TransportError>
    where
        Dev: FidoDevice,
    {
        if input.is_empty() {
            return Err(Error::InputTooSmall).map_err(TransportError::Command);
        }

        let status: StatusCode = input[0].into();
        debug!("response status code: {:?}", status);
        if input.len() > 1 {
            if status.is_ok() {
                let assertion = from_slice(&input[1..]).map_err(Error::Parsing)?;
                // TODO(baloo): check assertion response does not have numberOfCredentials
                Ok(assertion)
            } else {
                let data: Value = from_slice(&input[1..]).map_err(Error::Parsing)?;
                Err(Error::StatusCode(status, Some(data))).map_err(TransportError::Command)
            }
        } else if status.is_ok() {
            Err(Error::InputTooSmall).map_err(TransportError::Command)
        } else {
            Err(Error::StatusCode(status, None)).map_err(TransportError::Command)
        }
    }
}

pub enum U2FInfo {
    U2F_V2,
}

#[derive(Debug)]
// TODO(baloo): if one does not issue U2F_VERSION before makecredentials or getassertion, token
//              will return error (ConditionsNotSatified), test this in unit tests
pub struct GetVersion {}

impl Default for GetVersion {
    fn default() -> GetVersion {
        GetVersion {}
    }
}

impl RequestCtap1 for GetVersion {
    type Output = U2FInfo;

    fn handle_response_ctap1(
        &self,
        _status: Result<(), ApduErrorStatus>,
        input: &[u8],
    ) -> Result<Self::Output, Retryable<TransportError>> {
        if input.is_empty() {
            return Err(Error::InputTooSmall)
                .map_err(TransportError::Command)
                .map_err(Retryable::Error);
        }

        let expected = CString::new("U2F_V2")
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "null data in version"))
            .map_err(|e| TransportError::IO(None, e))
            .map_err(Retryable::Error)?;

        match CString::new(input)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "null data in version"))
            .map_err(|e| TransportError::IO(None, e))
            .map_err(Retryable::Error)?
        {
            ref data if data == &expected => Ok(U2FInfo::U2F_V2),
            _ => Err(io::Error::new(io::ErrorKind::Other, "unexpected version"))
                .map_err(|e| TransportError::IO(None, e))
                .map_err(Retryable::Error),
        }
    }

    fn apdu_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, transport::Error>
    where
        Dev: FidoDevice,
    {
        let flags = 0;

        let cmd = U2F_VERSION;
        let apdu = U2FAPDUHeader::serialize(cmd, flags, &[])?;

        Ok(apdu)
    }
}

#[derive(Debug)]
pub struct GetInfo {}

impl Default for GetInfo {
    fn default() -> GetInfo {
        GetInfo {}
    }
}

impl RequestCtap2 for GetInfo {
    type Output = AuthenticatorInfo;

    fn command() -> Command {
        Command::GetInfo
    }

    fn wire_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, transport::Error>
    where
        Dev: FidoDevice,
    {
        Ok(Vec::new())
    }

    fn handle_response_ctap2<Dev>(
        &self,
        _dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, TransportError>
    where
        Dev: FidoDevice,
    {
        if input.is_empty() {
            return Err(Error::InputTooSmall).map_err(TransportError::Command);
        }

        let status: StatusCode = input[0].into();
        debug!("response status code: {:?}", status);
        if input.len() > 1 {
            if status.is_ok() {
                trace!(
                    "parsing authenticator info data: {}",
                    pretty_hex(&&input[1..])
                );
                let authenticator_info = from_slice(&input[1..]).map_err(Error::Parsing)?;
                Ok(authenticator_info)
            } else {
                let data: Value = from_slice(&input[1..]).map_err(Error::Parsing)?;
                Err(Error::StatusCode(status, Some(data))).map_err(TransportError::Command)
            }
        } else if status.is_ok() {
            Err(Error::InputTooSmall).map_err(TransportError::Command)
        } else {
            Err(Error::StatusCode(status, None)).map_err(TransportError::Command)
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthenticatorOptions {
    /// Indicates that the device is attached to the client and therefore can’t
    /// be removed and used on another client.
    #[serde(rename = "plat")]
    platform_device: bool,
    /// Indicates that the device is capable of storing keys on the device
    /// itself and therefore can satisfy the authenticatorGetAssertion request
    /// with allowList parameter not specified or empty.
    #[serde(rename = "rk")]
    resident_key: bool,

    /// Client PIN:
    ///  If present and set to true, it indicates that the device is capable of
    ///   accepting a PIN from the client and PIN has been set.
    ///  If present and set to false, it indicates that the device is capable of
    ///   accepting a PIN from the client and PIN has not been set yet.
    ///  If absent, it indicates that the device is not capable of accepting a
    ///   PIN from the client.
    /// Client PIN is one of the ways to do user verification.
    #[serde(rename = "clientPin")]
    client_pin: Option<bool>,

    /// Indicates that the device is capable of testing user presence.
    #[serde(rename = "up")]
    user_presence: bool,

    /// Indicates that the device is capable of verifying the user within
    /// itself. For example, devices with UI, biometrics fall into this
    /// category.
    ///  If present and set to true, it indicates that the device is capable of
    ///   user verification within itself and has been configured.
    ///  If present and set to false, it indicates that the device is capable of
    ///   user verification within itself and has not been yet configured. For
    ///   example, a biometric device that has not yet been configured will
    ///   return this parameter set to false.
    ///  If absent, it indicates that the device is not capable of user
    ///   verification within itself.
    /// A device that can only do Client PIN will not return the "uv" parameter.
    /// If a device is capable of verifying the user within itself as well as
    /// able to do Client PIN, it will return both "uv" and the Client PIN
    /// option.
    #[serde(rename = "uv")]
    user_verification: Option<bool>,
}

impl Default for AuthenticatorOptions {
    fn default() -> Self {
        AuthenticatorOptions {
            platform_device: false,
            resident_key: false,
            client_pin: None,
            user_presence: true,
            user_verification: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatorInfo {
    versions: Vec<String>,
    extensions: Vec<String>,
    aaguid: AAGuid,
    options: AuthenticatorOptions,
    max_msg_size: Option<usize>,
    pin_protocols: Vec<u32>,
}

impl AuthenticatorInfo {
    /// Checks if client pin is set, if set platform is expected to send pin
    /// along with all make credentials or get attestation commands
    pub fn client_pin_set(&self) -> bool {
        self.options.client_pin == Some(true)
    }
}

impl<'de> Deserialize<'de> for AuthenticatorInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AuthenticatorInfoVisitor;

        impl<'de> Visitor<'de> for AuthenticatorInfoVisitor {
            type Value = AuthenticatorInfo;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut versions = Vec::new();
                let mut extensions = Vec::new();
                let mut aaguid = None;
                let mut options = AuthenticatorOptions::default();
                let mut max_msg_size = None;
                let mut pin_protocols = Vec::new();

                while let Some(key) = map.next_key()? {
                    match key {
                        1 => {
                            if !versions.is_empty() {
                                return Err(de::Error::duplicate_field("versions"));
                            }
                            versions = map.next_value()?;
                        }
                        2 => {
                            if !extensions.is_empty() {
                                return Err(de::Error::duplicate_field("extensions"));
                            }
                            extensions = map.next_value()?;
                        }
                        3 => {
                            if aaguid.is_some() {
                                return Err(de::Error::duplicate_field("aaguid"));
                            }
                            aaguid = Some(map.next_value()?);
                        }
                        4 => {
                            options = map.next_value()?;
                        }
                        5 => {
                            max_msg_size = Some(map.next_value()?);
                        }
                        6 => {
                            pin_protocols = map.next_value()?;
                        }
                        k => return Err(M::Error::custom(format!("unexpected key: {:?}", k))),
                    }
                }

                if versions.is_empty() {
                    return Err(M::Error::custom(
                        "expected at least one version, got none".to_string(),
                    ));
                }

                if let Some(aaguid) = aaguid {
                    Ok(AuthenticatorInfo {
                        versions,
                        extensions,
                        aaguid,
                        options,
                        max_msg_size,
                        pin_protocols,
                    })
                } else {
                    Err(M::Error::custom("No AAGuid specified".to_string()))
                }
            }
        }

        deserializer.deserialize_bytes(AuthenticatorInfoVisitor)
    }
}

#[derive(Debug)]
pub enum Error {
    InputTooSmall,
    UnsupportedPinProtocol,
    ECDH,
    MissingRequiredField(&'static str),
    Parsing(error::Error),
    Serialization(error::Error),
    Cose(cose::Error),
    StatusCode(StatusCode, Option<Value>),
    Openssl(ErrorStack),
    Pin(PinError),
    Json(json::Error),
}

impl Error {
    pub fn device_busy(&self) -> bool {
        match *self {
            Error::StatusCode(ref s, _) => s.device_busy(),
            _ => false,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InputTooSmall => write!(f, "CommandError: Input is too small"),
            Error::ECDH => write!(f, "CommandError: ecdh error"),
            Error::UnsupportedPinProtocol => {
                write!(f, "CommandError: Pin protocol is not supported")
            }
            Error::MissingRequiredField(field) => {
                write!(f, "CommandError: Missing required field {}", field)
            }
            Error::Parsing(ref e) => write!(f, "CommandError: Error while parsing: {}", e),
            Error::Serialization(ref e) => {
                write!(f, "CommandError: Error while serializing: {}", e)
            }
            Error::Cose(ref e) => write!(f, "CommandError: COSE: {}", e),
            Error::Openssl(ref e) => write!(f, "CommandError: openssl: {}", e),
            Error::StatusCode(ref code, ref value) => {
                write!(f, "CommandError: Unexpected code: {:?} ({:?})", code, value)
            }
            Error::Pin(ref p) => write!(f, "CommandError: Pin error: {}", p),
            Error::Json(ref e) => write!(f, "CommandError: Json serializing error: {}", e),
        }
    }
}

impl StdErrorT for Error {
    fn description(&self) -> &str {
        match *self {
            Error::InputTooSmall => "CommandError: Input is too small",
            Error::ECDH => "CommandError: ecdh error",
            Error::UnsupportedPinProtocol => "CommandError: Pin protocol is not supported",
            Error::MissingRequiredField(_) => "CommandError: Missing required field",
            Error::Parsing(ref e) => e.description(),
            Error::Serialization(ref e) => e.description(),
            Error::Cose(ref e) => e.description(),
            Error::Openssl(_) => "CommandError: openssl error",
            Error::StatusCode(_, _) => "CommandError: unexpected status code",
            Error::Pin(ref p) => p.description(),
            Error::Json(ref j) => j.description(),
        }
    }
}

impl From<error::Error> for Error {
    fn from(e: error::Error) -> Error {
        Error::Parsing(e)
    }
}

impl From<cose::Error> for Error {
    fn from(e: cose::Error) -> Error {
        Error::Cose(e)
    }
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Error {
        Error::Openssl(e)
    }
}

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
    fn as_client_pin(&self) -> Result<ClientPIN, Error>;
    fn parse_response_payload(&self, input: &[u8]) -> Result<Self::Output, Error>;
}

struct ClientPinResponse {
    key_agreement: Option<cose::PublicKey>,
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
                                return Err(de::Error::duplicate_field("key_agreement"));
                            }
                            key_agreement = map.next_value()?;
                        }
                        2 => {
                            if pin_token.is_some() {
                                return Err(de::Error::duplicate_field("pin_token"));
                            }
                            pin_token = map.next_value()?;
                        }
                        3 => {
                            if retries.is_some() {
                                return Err(de::Error::duplicate_field("retries"));
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
    pub fn new(info: &AuthenticatorInfo) -> Result<Self, Error> {
        if info.pin_protocols.contains(&1) {
            Ok(GetKeyAgreement { pin_protocol: 1 })
        } else {
            Err(Error::UnsupportedPinProtocol)
        }
    }
}

impl ClientPINSubCommand for GetKeyAgreement {
    type Output = KeyAgreement;

    fn as_client_pin(&self) -> Result<ClientPIN, Error> {
        Ok(ClientPIN {
            pin_protocol: self.pin_protocol,
            subcommand: PINSubcommand::GetKeyAgreement,
            ..ClientPIN::default()
        })
    }

    fn parse_response_payload(&self, input: &[u8]) -> Result<Self::Output, Error> {
        let value: Value = from_slice(input).map_err(Error::Parsing)?;
        debug!("GetKeyAgreement::parse_response_payload {:?}", value);

        let get_pin_response: ClientPinResponse = from_slice(input).map_err(Error::Parsing)?;
        if let Some(key_agreement) = get_pin_response.key_agreement {
            Ok(KeyAgreement(key_agreement))
        } else {
            Err(Error::MissingRequiredField("key_agreement"))
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
    ) -> Result<Self, Error> {
        if info.pin_protocols.contains(&1) {
            Ok(GetPinToken {
                pin_protocol: 1,
                shared_secret,
                pin,
            })
        } else {
            Err(Error::UnsupportedPinProtocol)
        }
    }
}

impl<'sc, 'pin> ClientPINSubCommand for GetPinToken<'sc, 'pin> {
    type Output = PinToken;

    fn as_client_pin(&self) -> Result<ClientPIN, Error> {
        let iv = [0u8; 16];
        let input = self.pin.for_pin_token();
        trace!("pin_hash = {}", pretty_hex(&input.as_ref()));
        let pin_hash_enc = self.shared_secret.encrypt(input.as_ref(), &iv[..])?;
        trace!("pin_hash_enc = {}", pretty_hex(&pin_hash_enc));

        Ok(ClientPIN {
            pin_protocol: self.pin_protocol,
            subcommand: PINSubcommand::GetPINToken,
            key_agreement: Some(self.shared_secret.my_public_key().clone()),
            pin_hash_enc: Some(pin_hash_enc.into()),
            ..ClientPIN::default()
        })
    }

    fn parse_response_payload(&self, input: &[u8]) -> Result<Self::Output, Error> {
        let value: Value = from_slice(input).map_err(Error::Parsing)?;
        debug!("GetKeyAgreement::parse_response_payload {:?}", value);

        let get_pin_response: ClientPinResponse = from_slice(input).map_err(Error::Parsing)?;
        if let Some(encrypted_pin_token) = get_pin_response.pin_token {
            let iv = [0u8; 16];
            let pin_token = self
                .shared_secret
                .decrypt(encrypted_pin_token.as_ref(), &iv[..])?;
            let pin_token = PinToken(pin_token);
            Ok(pin_token)
        } else {
            Err(Error::MissingRequiredField("key_agreement"))
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

    fn wire_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, transport::Error>
    where
        Dev: FidoDevice,
    {
        let client_pin = self.as_client_pin()?;
        let output = to_vec(&client_pin).map_err(Error::Serialization)?;
        trace!("client subcommmand: {}", pretty_hex(&output));

        Ok(output)
    }

    fn handle_response_ctap2<Dev>(
        &self,
        _dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, TransportError>
    where
        Dev: FidoDevice,
    {
        trace!("Client pin subcomand response: {}", pretty_hex(&input));

        if input.is_empty() {
            return Err(Error::InputTooSmall).map_err(TransportError::Command);
        }
        let status: StatusCode = input[0].into();
        debug!("response status code: {:?}", status);
        if input.len() > 1 {
            if status.is_ok() {
                <T as ClientPINSubCommand>::parse_response_payload(self, &input[1..])
                    .map_err(TransportError::Command)
            } else {
                let data: Value = from_slice(&input[1..]).map_err(Error::Parsing)?;
                Err(Error::StatusCode(status, Some(data))).map_err(TransportError::Command)
            }
        } else if status.is_ok() {
            Err(Error::InputTooSmall).map_err(TransportError::Command)
        } else {
            Err(Error::StatusCode(status, None)).map_err(TransportError::Command)
        }
    }
}

#[derive(Debug)]
pub struct KeyAgreement(cose::PublicKey);

impl KeyAgreement {
    pub fn shared_secret(&self) -> Result<ECDHSecret, Error> {
        self.0
            .complete_handshake()
            .map_err(|_| Error::ECDH)
            .map(ECDHSecret)
    }
}

#[derive(Debug, Clone)]
pub struct ECDHSecret(agreement::ECDHSecret);

impl ECDHSecret {
    pub fn my_public_key(&self) -> &PublicKey {
        self.0.my_public_key()
    }

    pub fn encrypt(&self, input: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = Cipher::aes_256_cbc();

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
        Ok(output)
    }

    pub fn decrypt(&self, input: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = Cipher::aes_256_cbc();

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

        Ok(output)
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
    pub fn auth(&self, client_hash_data: &ClientDataHash) -> Result<PinAuth, PinError> {
        if self.0.len() < 4 {
            return Err(PinError::PinIsTooShort);
        }

        let bytes = self.0.as_slice();
        if bytes.len() > 64 {
            return Err(PinError::PinIsTooLong(bytes.len()));
        }
        let mut mac =
            Hmac::<Sha256>::new_varkey(self.as_ref()).map_err(|_| PinError::InvalidKeyLen)?;
        mac.input(client_hash_data.as_ref());

        let mut out = [0u8; 16];
        out.copy_from_slice(&mac.result().code().as_slice()[0..16]);

        Ok(PinAuth(out))
    }
}

impl AsRef<[u8]> for PinToken {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(test)]
pub mod test {
    use serde_cbor::de::from_slice;

    use super::{AuthenticatorInfo, MakeCredentials, Request};
    use crate::ctap::{CollectedClientData, Origin, WebauthnType};
    use crate::ctap2::server::{
        Alg, PublicKeyCredentialParameters, RelyingParty, RelyingPartyData, User,
    };
    use crate::transport::hid::HIDDevice;
    use crate::transport::platform::device::Device;
    use crate::transport::platform::TestCase;

    pub const MAKE_CREDENTIALS_SAMPLE_RESPONSE: [u8; 666] =
        include!("tests/MAKE_CREDENTIALS_SAMPLE_RESPONSE,in");

    #[test]
    fn parse_response() {
        let challenge = vec![0, 1, 2, 3];
        let req = MakeCredentials::new(
            CollectedClientData {
                type_: WebauthnType::Create,
                challenge: challenge.clone().into(),
                origin: Origin::Some(String::from("https://www.example.com")),
                token_binding: None,
            },
            RelyingParty::Data(RelyingPartyData {
                id: String::from("example.com"),
            }),
            Some(User {
                id: vec![0],
                icon: None,
                name: String::from("j.doe"),
                display_name: None,
            }),
            vec![PublicKeyCredentialParameters { alg: Alg::ES256 }],
            Vec::new(),
            None,
            None,
        );
        let mut device = Device::new(TestCase::WriteError).unwrap();
        let reply = req.handle_response(&mut device, &MAKE_CREDENTIALS_SAMPLE_RESPONSE[..]);

        assert!(reply.is_ok());
        let (reply, _) = reply.unwrap();

        assert_eq!(
            &reply.auth_data.rp_id_hash.0,
            &[
                0xc2, 0x89, 0xc5, 0xca, 0x9b, 0x04, 0x60, 0xf9, 0x34, 0x6a, 0xb4, 0xe4, 0x2d, 0x84,
                0x27, 0x43, 0x40, 0x4d, 0x31, 0xf4, 0x84, 0x68, 0x25, 0xa6, 0xd0, 0x65, 0xbe, 0x59,
                0x7a, 0x87, 0x5, 0x1d
            ]
        );
    }

    pub const AUTHENTICATOR_INFO_PAYLOAD: [u8; 85] =
        include!("tests/AUTHENTICATOR_INFO_PAYLOAD.in");

    #[test]
    fn parse_authenticator_info() {
        let authenticator_info: AuthenticatorInfo =
            from_slice(&AUTHENTICATOR_INFO_PAYLOAD[..]).unwrap();

        println!("authenticator_info {:?}", authenticator_info);
        //assert_eq!(true, false);
    }
}
