use crate::consts::Capability;
use crate::ctap2::commands::get_info::AuthenticatorInfo;
use crate::ctap2::commands::{Request, RequestCtap1, RequestCtap2};
use crate::ctap2::crypto::ECDHSecret;
use crate::u2ftypes::U2FDevice;
use std::fmt;

pub mod errors;
pub mod hid;

use errors::HIDError;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
pub mod hidproto;

#[cfg(target_os = "linux")]
#[path = "linux/mod.rs"]
pub mod platform;

#[cfg(target_os = "freebsd")]
#[path = "freebsd/mod.rs"]
pub mod platform;

#[cfg(target_os = "netbsd")]
#[path = "netbsd/mod.rs"]
pub mod platform;

#[cfg(target_os = "openbsd")]
#[path = "openbsd/mod.rs"]
pub mod platform;

#[cfg(target_os = "macos")]
#[path = "macos/mod.rs"]
pub mod platform;

#[cfg(target_os = "windows")]
#[path = "windows/mod.rs"]
pub mod platform;

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "windows"
)))]
#[path = "stub/mod.rs"]
pub mod platform;

#[allow(dead_code)]
#[derive(Debug)]
pub enum Nonce {
    CreateRandom,
    Use([u8; 8]),
}

// TODO(MS): This is the lazy way: FidoDevice currently only extends U2FDevice by more functions,
//           but the goal is to remove U2FDevice entirely and copy over the trait-definition here
pub(crate) trait FidoDevice: U2FDevice
where
    Self: fmt::Debug,
{
    type BuildParameters;

    fn send_msg<'msg, Out, Req: Request<Out>>(&mut self, msg: &'msg Req) -> Result<Out, HIDError> {
        if !self.initialized() {
            return Err(HIDError::DeviceNotInitialized);
        }

        if self.supports_ctap2() {
            self.send_cbor(msg)
        } else {
            self.send_apdu(msg)
        }
    }

    fn send_apdu<'msg, Req: RequestCtap1>(
        &mut self,
        msg: &'msg Req,
    ) -> Result<Req::Output, HIDError>;
    fn send_cbor<'msg, Req: RequestCtap2>(
        &mut self,
        msg: &'msg Req,
    ) -> Result<Req::Output, HIDError>;

    fn new(parameters: Self::BuildParameters) -> Result<Self, HIDError>
    where
        Self::BuildParameters: Sized,
        Self: Sized;

    fn init(&mut self, nonce: Nonce) -> Result<(), HIDError>;

    fn initialized(&self) -> bool;
    fn supports_ctap1(&self) -> bool {
        // CAPABILITY_NMSG:
        // If set to 1, authenticator DOES NOT implement U2FHID_MSG function
        !self.get_device_info().cap_flags.contains(Capability::NMSG)
    }

    fn supports_ctap2(&self) -> bool {
        self.get_device_info().cap_flags.contains(Capability::CBOR)
    }

    fn get_authenticator_info(&self) -> Option<&AuthenticatorInfo>;
    fn set_authenticator_info(&mut self, authenticator_info: AuthenticatorInfo);
    fn set_shared_secret(&mut self, secret: ECDHSecret);
    fn get_shared_secret(&self) -> Option<&ECDHSecret>;
}
