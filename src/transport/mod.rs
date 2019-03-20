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

use crate::ctap::Version;
use crate::ctap2::commands::{AuthenticatorInfo, ECDHSecret, Error as CommandError, Request};

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
    UnexpectedStatus(u8),
    Command(CommandError),
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
            Error::UnexpectedStatus(s) => write!(f, "Error: Unexpected status: {}", s),
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
            Error::UnexpectedStatus(_) => "Error: Unexpected status",
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
    pub fn has_fido2(&self) -> bool {
        self.intersects(ProtocolSupport::FIDO2)
    }
}

pub(crate) trait FidoDevice
where
    Self: fmt::Debug,
{
    type BuildParameters;

    fn send_msg<'msg, Req: Request>(&mut self, msg: &'msg Req) -> Result<Req::Output, Error> {
        if !self.initialized() {
            return Err(Error::DeviceNotInitialized);
        }

        if msg.minimum_version() == Version::CTAP2 && !self.protocol_support().has_fido2() {
            info!("{:?} does not support Fido2 commands", self);
            return Err(Error::UnsupportedCommand);
        }

        if self.protocol_support().has_fido2() {
            self.send_cbor(msg)
        } else {
            self.send_apdu(msg)
        }
    }

    fn send_apdu<'msg, Req: Request>(&mut self, msg: &'msg Req) -> Result<Req::Output, Error>;
    fn send_cbor<'msg, Req: Request>(&mut self, msg: &'msg Req) -> Result<Req::Output, Error>;

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
