use crate::crypto::{CryptoError, PinUvAuthParam};
use crate::ctap2::client_data::ClientDataHash;
use crate::ctap2::commands::client_pin::{
    GetPinRetries, GetUvRetries, Pin, PinError, PinUvAuthTokenPermission,
};
use crate::errors::AuthenticatorError;
use crate::transport::errors::{ApduErrorStatus, HIDError};
use crate::transport::FidoDevice;
use serde_cbor::{error::Error as CborError, Value};
use serde_json as json;
use std::error::Error as StdErrorT;
use std::fmt;
use std::io::{Read, Write};

pub(crate) mod client_pin;
pub(crate) mod get_assertion;
pub(crate) mod get_info;
pub(crate) mod get_next_assertion;
pub(crate) mod get_version;
pub(crate) mod make_credentials;
pub(crate) mod reset;
pub(crate) mod selection;

pub trait Request<T>
where
    Self: fmt::Debug,
    Self: RequestCtap1<Output = T>,
    Self: RequestCtap2<Output = T>,
{
    fn is_ctap2_request(&self) -> bool;
}

/// Retryable wraps an error type and may ask manager to retry sending a
/// command, this is useful for ctap1 where token will reply with "condition not
/// sufficient" because user needs to press the button.
#[derive(Debug)]
pub enum Retryable<T> {
    Retry,
    Error(T),
}

impl<T> Retryable<T> {
    pub fn is_retry(&self) -> bool {
        matches!(*self, Retryable::Retry)
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

pub trait RequestCtap1: fmt::Debug {
    type Output;
    // E.g.: For GetAssertion, which key-handle is currently being tested
    type AdditionalInfo;

    /// Serializes a request into FIDO v1.x / CTAP1 / U2F format.
    ///
    /// See [`crate::u2ftypes::CTAP1RequestAPDU::serialize()`]
    fn ctap1_format<Dev>(&self, dev: &mut Dev) -> Result<(Vec<u8>, Self::AdditionalInfo), HIDError>
    where
        Dev: FidoDevice + Read + Write + fmt::Debug;

    /// Deserializes a response from FIDO v1.x / CTAP1 / U2Fv2 format.
    fn handle_response_ctap1(
        &self,
        status: Result<(), ApduErrorStatus>,
        input: &[u8],
        add_info: &Self::AdditionalInfo,
    ) -> Result<Self::Output, Retryable<HIDError>>;
}

pub trait RequestCtap2: fmt::Debug {
    type Output;

    fn command() -> Command;

    fn wire_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, HIDError>
    where
        Dev: FidoDevice + Read + Write + fmt::Debug;

    fn handle_response_ctap2<Dev>(
        &self,
        dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, HIDError>
    where
        Dev: FidoDevice + Read + Write + fmt::Debug;
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum PinUvAuthResult {
    /// Request is CTAP1 and does not need PinUvAuth
    RequestIsCtap1,
    /// Device is not capable of CTAP2
    DeviceIsCtap1,
    /// Device does not support UV or PINs
    NoAuthTypeSupported,
    /// Request doesn't want user verification (uv = "discouraged")
    NoAuthRequired,
    /// Device is CTAP2.0 and has internal UV capability
    UsingInternalUv,
    /// Successfully established PinUvAuthToken via GetPinToken (CTAP2.0)
    SuccessGetPinToken,
    /// Successfully established PinUvAuthToken via UV (CTAP2.1)
    SuccessGetPinUvAuthTokenUsingUvWithPermissions,
    /// Successfully established PinUvAuthToken via Pin (CTAP2.1)
    SuccessGetPinUvAuthTokenUsingPinWithPermissions,
}

pub(crate) trait PinUvAuthCommand: RequestCtap2 {
    fn pin(&self) -> &Option<Pin>;
    fn set_pin(&mut self, pin: Option<Pin>);
    fn set_pin_uv_auth_param(&mut self, pin_uv_auth_param: Option<PinUvAuthParam>);
    fn client_data_hash(&self) -> ClientDataHash;
    fn set_uv_option(&mut self, uv: Option<bool>);
    fn get_uv_option(&mut self) -> Option<bool>;
    fn get_rp_id(&self) -> Option<&String>;

    /// If Ok() is returned, the request can be sent to the device
    /// If Err() is returned, either cancel the operation or ask the user for a PIN
    fn determine_pin_uv_auth<D: FidoDevice>(
        &mut self,
        dev: &mut D,
        skip_uv: bool,
        permission: PinUvAuthTokenPermission,
    ) -> Result<PinUvAuthResult, AuthenticatorError> {
        // In case we error out in the middle
        self.set_pin_uv_auth_param(None);

        // CTAP1/U2F-only devices do not support PinUvAuth, so we skip it
        if !dev.supports_ctap2() {
            self.set_pin_uv_auth_param(None);
            return Ok(PinUvAuthResult::DeviceIsCtap1);
        }

        // TODO: API needs a better way to express "uv = discouraged"
        if self.get_uv_option() == Some(false) {
            // MakeCredentials:
            // "[..] the Relying Party wants to create a non-discoverable credential and not require user verification
            // (e.g., by setting options.authenticatorSelection.userVerification to "discouraged" in the WebAuthn API),
            // the platform invokes the authenticatorMakeCredential operation using the marshalled input parameters along
            // with the "uv" option key set to false and terminate these steps."
            // GetAssertion:
            // "[..] the Relying Party does not wish to require user verification (e.g., by setting options.userVerification
            // to "discouraged" in the WebAuthn API), the platform invokes the authenticatorGetAssertion operation using
            // the marshalled input parameters along with an absent "uv" option key."
            if Self::command() == Command::GetAssertion {
                self.set_uv_option(None);
            };
            return Ok(PinUvAuthResult::NoAuthRequired);
        }

        let info = dev
            .get_authenticator_info()
            .ok_or(AuthenticatorError::HIDError(HIDError::DeviceNotInitialized))?;

        // Only use UV, if the device supports it and we don't skip it
        // which happens as a fallback, if UV-usage failed too many times
        // Note: In theory, we could also repeatedly query GetInfo here and check
        //       if uv is set to Some(true), as tokens should set it to Some(false)
        //       if UV is blocked (too many failed attempts). But the CTAP2.0-spec is
        //       vague and I don't trust all tokens to implement it that way. So we
        //       keep track of it ourselves, using `skip_uv`.
        let supports_uv = info.options.user_verification == Some(true);
        let supports_pin = info.options.client_pin.is_some();
        let pin_configured = info.options.client_pin == Some(true);

        // Device does not support any auth-method
        if !pin_configured && !supports_uv {
            // We'll send it to the device anyways, and let it error out (or magically work)
            return Ok(PinUvAuthResult::NoAuthTypeSupported);
        }

        let (res, pin_auth_token) = if info.options.pin_uv_auth_token == Some(true) {
            if !skip_uv && supports_uv {
                // CTAP 2.1 - UV
                let pin_auth_token = dev
                    .get_pin_uv_auth_token_using_uv_with_permissions(permission, self.get_rp_id());
                (
                    PinUvAuthResult::SuccessGetPinUvAuthTokenUsingUvWithPermissions,
                    pin_auth_token,
                )
            } else if supports_pin && pin_configured {
                // CTAP 2.1 - PIN
                let pin_auth_token = dev.get_pin_uv_auth_token_using_pin_with_permissions(
                    self.pin(),
                    permission,
                    self.get_rp_id(),
                );
                (
                    PinUvAuthResult::SuccessGetPinUvAuthTokenUsingPinWithPermissions,
                    pin_auth_token,
                )
            } else {
                return Ok(PinUvAuthResult::NoAuthTypeSupported);
            }
        } else {
            // CTAP 2.0 fallback
            if !skip_uv && supports_uv && self.pin().is_none() {
                // If the device supports internal user-verification (e.g. fingerprints),
                // skip PIN-stuff

                // We may need the shared secret for HMAC-extension, so we
                // have to establish one
                let _shared_secret = dev.establish_shared_secret()?;
                return Ok(PinUvAuthResult::UsingInternalUv);
            }

            let pin_auth_token = dev.get_pin_token(self.pin());
            (PinUvAuthResult::SuccessGetPinToken, pin_auth_token)
        };

        let pin_auth_param = pin_auth_token
            .map_err(|e| repackage_pin_errors(dev, e))?
            .derive(self.client_data_hash().as_ref())
            .map_err(CommandError::Crypto)?;
        self.set_pin_uv_auth_param(Some(pin_auth_param));
        // CTAP 2.0 spec is a bit vague here, but CTAP 2.1 is very specific, that the request
        // should either include pinAuth OR uv=true, but not both at the same time.
        // Do not set user_verification, if pinAuth is provided
        self.set_uv_option(None);
        Ok(res)
    }
}

pub(crate) fn repackage_pin_errors<D: FidoDevice>(
    dev: &mut D,
    error: HIDError,
) -> AuthenticatorError {
    match error {
        HIDError::Command(CommandError::StatusCode(StatusCode::PinInvalid, _)) => {
            // If the given PIN was wrong, determine no. of left retries
            let cmd = GetPinRetries::new();
            let retries = dev.send_cbor(&cmd).ok(); // If we got retries, wrap it in Some, otherwise ignore err
            AuthenticatorError::PinError(PinError::InvalidPin(retries))
        }
        HIDError::Command(CommandError::StatusCode(StatusCode::PinAuthBlocked, _)) => {
            AuthenticatorError::PinError(PinError::PinAuthBlocked)
        }
        HIDError::Command(CommandError::StatusCode(StatusCode::PinBlocked, _)) => {
            AuthenticatorError::PinError(PinError::PinBlocked)
        }
        HIDError::Command(CommandError::StatusCode(StatusCode::PinRequired, _)) => {
            AuthenticatorError::PinError(PinError::PinRequired)
        }
        HIDError::Command(CommandError::StatusCode(StatusCode::PinNotSet, _)) => {
            AuthenticatorError::PinError(PinError::PinNotSet)
        }
        HIDError::Command(CommandError::StatusCode(StatusCode::PinAuthInvalid, _)) => {
            AuthenticatorError::PinError(PinError::PinAuthInvalid)
        }
        HIDError::Command(CommandError::StatusCode(StatusCode::UvInvalid, _)) => {
            // If the internal UV failed, determine no. of left retries
            let cmd = GetUvRetries::new();
            let retries = dev.send_cbor(&cmd).ok(); // If we got retries, wrap it in Some, otherwise ignore err
            AuthenticatorError::PinError(PinError::InvalidUv(retries))
        }
        HIDError::Command(CommandError::StatusCode(StatusCode::UvBlocked, _)) => {
            AuthenticatorError::PinError(PinError::UvBlocked)
        }
        // TODO(MS): Add "PinPolicyViolated"
        err => AuthenticatorError::HIDError(err),
    }
}

// Spec: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticator-api
// and: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticator-api
#[repr(u8)]
#[derive(Debug, PartialEq, Clone)]
pub enum Command {
    MakeCredentials = 0x01,
    GetAssertion = 0x02,
    GetInfo = 0x04,
    ClientPin = 0x06,
    Reset = 0x07,
    GetNextAssertion = 0x08,
    Selection = 0x0B,
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
    /// built-in user verification is disabled.
    UvBlocked,
    /// A checksum did not match.
    IntegrityFailure,
    /// The requested subcommand is either invalid or not implemented.
    InvalidSubcommand,
    /// built-in user verification unsuccessful. The platform SHOULD retry.
    UvInvalid,
    /// The permissions parameter contains an unauthorized permission.
    UnauthorizedPermission,
    /// Other unspecified error.
    Other,

    /// Unknown status.
    Unknown(u8),
}

impl StatusCode {
    fn is_ok(&self) -> bool {
        matches!(*self, StatusCode::OK)
    }

    fn device_busy(&self) -> bool {
        matches!(*self, StatusCode::ChannelBusy)
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
            0x3C => StatusCode::UvBlocked,
            0x3D => StatusCode::IntegrityFailure,
            0x3E => StatusCode::InvalidSubcommand,
            0x3F => StatusCode::UvInvalid,
            0x40 => StatusCode::UnauthorizedPermission,
            0x7F => StatusCode::Other,
            othr => StatusCode::Unknown(othr),
        }
    }
}

#[cfg(test)]
impl From<StatusCode> for u8 {
    fn from(v: StatusCode) -> u8 {
        match v {
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
            StatusCode::UvBlocked => 0x3C,
            StatusCode::IntegrityFailure => 0x3D,
            StatusCode::InvalidSubcommand => 0x3E,
            StatusCode::UvInvalid => 0x3F,
            StatusCode::UnauthorizedPermission => 0x40,
            StatusCode::Other => 0x7F,

            StatusCode::Unknown(othr) => othr,
        }
    }
}

#[derive(Debug)]
pub enum CommandError {
    InputTooSmall,
    MissingRequiredField(&'static str),
    Deserializing(CborError),
    Serializing(CborError),
    StatusCode(StatusCode, Option<Value>),
    Json(json::Error),
    Crypto(CryptoError),
    UnsupportedPinProtocol,
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CommandError::InputTooSmall => write!(f, "CommandError: Input is too small"),
            CommandError::MissingRequiredField(field) => {
                write!(f, "CommandError: Missing required field {field}")
            }
            CommandError::Deserializing(ref e) => {
                write!(f, "CommandError: Error while parsing: {e}")
            }
            CommandError::Serializing(ref e) => {
                write!(f, "CommandError: Error while serializing: {e}")
            }
            CommandError::StatusCode(ref code, ref value) => {
                write!(f, "CommandError: Unexpected code: {code:?} ({value:?})")
            }
            CommandError::Json(ref e) => write!(f, "CommandError: Json serializing error: {e}"),
            CommandError::Crypto(ref e) => write!(f, "CommandError: Crypto error: {e:?}"),
            CommandError::UnsupportedPinProtocol => {
                write!(f, "CommandError: Pin protocol is not supported")
            }
        }
    }
}

impl StdErrorT for CommandError {}
