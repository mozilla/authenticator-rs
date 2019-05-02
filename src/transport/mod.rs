use std::error::Error as ErrorT;
use std::fmt;
use std::io;
use std::path;

pub mod hid;

#[cfg(all(not(test), target_os = "linux"))]
#[path = "linux/mod.rs"]
pub mod platform;

#[cfg(all(not(test), target_os = "freebsd"))]
#[path = "freebsd/mod.rs"]
pub mod platform;

#[cfg(all(not(test), target_os = "macos"))]
#[path = "macos/mod.rs"]
pub mod platform;

#[cfg(all(not(test), target_os = "windows"))]
#[path = "windows/mod.rs"]
pub mod platform;

#[cfg(test)]
#[path = "test/mod.rs"]
pub mod platform;

// TODO(baloo): do we really need this? have to ask jcj
//#[cfg(not(any(
//    test,
//    target_os = "linux",
//    target_os = "freebsd",
//    target_os = "macos",
//    target_os = "windows"
//)))]
//#[path = "stub/mod.rs"]
//pub mod platform;

#[cfg(all(any(target_os = "linux", target_os = "freebsd"), not(test)))]
pub mod hidproto;

use crate::consts::{SW_CONDITIONS_NOT_SATISFIED, SW_NO_ERROR, SW_WRONG_DATA, SW_WRONG_LENGTH};
use crate::ctap::Version;
use crate::ctap2::commands::{
    AuthenticatorInfo, ECDHSecret, Error as CommandError, Request, RequestCtap1, RequestCtap2,
};

#[derive(Debug, PartialEq, Eq)]
pub enum ApduErrorStatus {
    ConditionsNotSatisfied,
    WrongData,
    WrongLength,
    Unknown([u8; 2]),
}

impl ApduErrorStatus {
    pub fn from(status: [u8; 2]) -> Result<(), ApduErrorStatus> {
        match status {
            s if s == SW_NO_ERROR => Ok(()),
            s if s == SW_CONDITIONS_NOT_SATISFIED => Err(ApduErrorStatus::ConditionsNotSatisfied),
            s if s == SW_WRONG_DATA => Err(ApduErrorStatus::WrongData),
            s if s == SW_WRONG_LENGTH => Err(ApduErrorStatus::WrongLength),
            other => Err(ApduErrorStatus::Unknown(other)),
        }
    }

    pub fn is_conditions_not_satisfied(&self) -> bool {
        match *self {
            ApduErrorStatus::ConditionsNotSatisfied => true,
            _ => false,
        }
    }
}
impl fmt::Display for ApduErrorStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ApduErrorStatus::ConditionsNotSatisfied => write!(f, "Apdu: condition not satisfied"),
            ApduErrorStatus::WrongData => write!(f, "Apdu: wrong data"),
            ApduErrorStatus::WrongLength => write!(f, "Apdu: wrong length"),
            ApduErrorStatus::Unknown(ref u) => write!(f, "Apdu: unknown error: {:?}", u),
        }
    }
}

impl ErrorT for ApduErrorStatus {
    fn description(&self) -> &str {
        match *self {
            ApduErrorStatus::ConditionsNotSatisfied => "Apdu: condition not satisfied",
            ApduErrorStatus::WrongData => "Apdu: wrong data",
            ApduErrorStatus::WrongLength => "Apdu: wrong length",
            ApduErrorStatus::Unknown(_) => "Apdu: unknown error",
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// Transport replied with a status not expected
    DeviceError,
    UnexpectedInitReplyLen,
    NonceMismatch,
    DeviceNotInitialized,
    #[cfg(not(test))]
    DeviceNotSupported,
    UnsupportedCommand,
    IO(Option<path::PathBuf>, io::Error),
    UnexpectedCmd(u8),
    Command(CommandError),
    ApduStatus(ApduErrorStatus),
}

impl Error {
    pub fn device_unsupported(&self) -> bool {
        match *self {
            Error::UnsupportedCommand => true,
            _ => false,
        }
    }

    pub fn unsupported_command(&self) -> bool {
        match *self {
            Error::UnsupportedCommand => true,
            _ => false,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IO(None, e)
    }
}

impl From<CommandError> for Error {
    fn from(e: CommandError) -> Error {
        Error::Command(e)
    }
}

impl From<ApduErrorStatus> for Error {
    fn from(e: ApduErrorStatus) -> Error {
        Error::ApduStatus(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnexpectedInitReplyLen => {
                write!(f, "Error: Unexpected reply len when initilizaling")
            }
            Error::NonceMismatch => write!(f, "Error: Nonce mismatch"),
            Error::DeviceError => write!(f, "Error: device returned error"),
            Error::DeviceNotInitialized => write!(f, "Error: using not initiliazed device"),
            #[cfg(not(test))]
            Error::DeviceNotSupported => {
                write!(f, "Error: requested operation is not available on device")
            }
            Error::UnsupportedCommand => {
                write!(f, "Error: command is not supported on this device")
            }
            Error::IO(ref p, ref e) => write!(f, "Error: Ioerror({:?}): {}", p, e),
            Error::Command(ref e) => write!(f, "Error: Error issuing command: {}", e),
            Error::UnexpectedCmd(s) => write!(f, "Error: Unexpected status: {}", s),
            Error::ApduStatus(ref status) => {
                write!(f, "Error: Unexpected apdu status: {:?}", status)
            }
        }
    }
}

impl ErrorT for Error {
    fn description(&self) -> &str {
        match *self {
            Error::UnexpectedInitReplyLen => "Error: Unexpected reply len when initilizaling",
            Error::NonceMismatch => "Error: Nonce mismatch",
            Error::DeviceError => "Error: device returned error",
            Error::DeviceNotInitialized => "Error: using not initiliazed device",
            #[cfg(not(test))]
            Error::DeviceNotSupported => "Error: requested operation is not available on device",
            Error::UnsupportedCommand => "Error: command is not supported on this device",
            Error::IO(_, ref e) => e.description(),
            Error::Command(ref e) => e.description(),
            Error::UnexpectedCmd(_) => "Error: Unexpected status",
            Error::ApduStatus(ref status) => status.description(),
        }
    }
}

bitflags! {
    pub struct ProtocolSupport: u8 {
        const FIDO1 = 0x01;
        const FIDO2 = 0x02;
    }
}

impl ProtocolSupport {
    pub fn has_fido1(&self) -> bool {
        self.contains(ProtocolSupport::FIDO1)
    }

    pub fn has_fido2(&self) -> bool {
        self.contains(ProtocolSupport::FIDO2)
    }
}

pub(crate) trait FidoDevice
where
    Self: fmt::Debug,
{
    type BuildParameters;

    fn send_msg<'msg, Out, Req: Request<Out>>(&mut self, msg: &'msg Req) -> Result<Out, Error> {
        if !self.initialized() {
            return Err(Error::DeviceNotInitialized);
        }

        // TODO(baloo): There is no logic in here, have to rework that
        if msg.minimum_version() == Version::CTAP2 && !self.protocol_support().has_fido2() {
            info!("{:?} does not support Fido2 commands", self);
            return Err(Error::UnsupportedCommand);
        }
        if msg.maximum_version() == Version::CTAP1 && !self.protocol_support().has_fido1() {
            info!("{:?} does not support Fido1 commands", self);
            return Err(Error::UnsupportedCommand);
        }

        if msg.maximum_version() != Version::CTAP1 && self.protocol_support().has_fido2() {
            self.send_cbor(msg)
        } else {
            self.send_apdu(msg)
        }
    }

    fn send_apdu<'msg, Req: RequestCtap1>(&mut self, msg: &'msg Req) -> Result<Req::Output, Error>;
    fn send_cbor<'msg, Req: RequestCtap2>(&mut self, msg: &'msg Req) -> Result<Req::Output, Error>;

    fn new(parameters: Self::BuildParameters) -> Result<Self, Error>
    where
        Self::BuildParameters: Sized,
        Self: Sized;

    fn init(&mut self) -> Result<(), Error>;

    fn initialized(&self) -> bool;
    fn initialize(&mut self);

    fn protocol_support(&self) -> ProtocolSupport;

    fn set_shared_secret(&mut self, secret: ECDHSecret);
    fn shared_secret(&self) -> Option<&ECDHSecret>;

    fn authenticator_info(&self) -> Option<&AuthenticatorInfo>;
    fn set_authenticator_info(&mut self, authenticator_info: AuthenticatorInfo);
}
