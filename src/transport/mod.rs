use crate::consts::{Capability, HIDCmd};
use crate::crypto::ECDHSecret;
use crate::ctap2::client_data::{Challenge, WebauthnType};
use crate::ctap2::commands::client_pin::PinAuth;
use crate::ctap2::commands::get_info::{AuthenticatorInfo, GetInfo};
use crate::ctap2::commands::get_version::GetVersion;
use crate::ctap2::commands::make_credentials::{
    MakeCredentials, MakeCredentialsExtensions, MakeCredentialsOptions,
};
use crate::ctap2::commands::{
    CommandError, PinAuthCommand, Request, RequestCtap1, RequestCtap2, Retryable, StatusCode,
};
use crate::ctap2::server::{
    PublicKeyCredentialParameters, RelyingParty, RelyingPartyWrapper, User,
};
use crate::transport::device_selector::BlinkResult;
use crate::transport::errors::{ApduErrorStatus, HIDError};
use crate::transport::hid::HIDDevice;
use crate::util::io_err;
use crate::CollectedClientData;
use std::thread;
use std::time::Duration;

pub mod device_selector;
pub mod errors;
pub mod hid;

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

#[derive(Debug)]
pub enum Nonce {
    CreateRandom,
    Use([u8; 8]),
}

// TODO(MS): This is the lazy way: FidoDevice currently only extends HIDDevice by more functions,
//           but the goal is to remove U2FDevice entirely and copy over the trait-definition here
pub trait FidoDevice: HIDDevice {
    fn send_msg<'msg, Out, Req: Request<Out>>(&mut self, msg: &'msg Req) -> Result<Out, HIDError> {
        if !self.initialized() {
            return Err(HIDError::DeviceNotInitialized);
        }

        if self.supports_ctap2() && msg.is_ctap2_request() {
            self.send_cbor(msg)
        } else {
            self.send_apdu(msg)
        }
    }

    fn send_cbor<'msg, Req: RequestCtap2>(
        &mut self,
        msg: &'msg Req,
    ) -> Result<Req::Output, HIDError> {
        debug!("sending {:?} to {:?}", msg, self);

        let mut data = msg.wire_format(self)?;
        let mut buf: Vec<u8> = Vec::with_capacity(data.len() + 1);
        // CTAP2 command
        buf.push(Req::command() as u8);
        // payload
        buf.append(&mut data);
        let buf = buf;

        let (cmd, resp) = self.sendrecv(HIDCmd::Cbor, &buf)?;
        debug!("got from {:?} status={:?}: {:?}", self, cmd, resp);
        if cmd == HIDCmd::Cbor {
            Ok(msg.handle_response_ctap2(self, &resp)?)
        } else {
            Err(HIDError::UnexpectedCmd(cmd.into()))
        }
    }

    fn send_apdu<'msg, Req: RequestCtap1>(
        &mut self,
        msg: &'msg Req,
    ) -> Result<Req::Output, HIDError> {
        debug!("sending {:?} to {:?}", msg, self);
        let data = msg.apdu_format(self)?;

        loop {
            let (cmd, mut data) = self.sendrecv(HIDCmd::Msg, &data)?;
            debug!("got from {:?} status={:?}: {:?}", self, cmd, data);
            if cmd == HIDCmd::Msg {
                if data.len() < 2 {
                    return Err(io_err("Unexpected Response: shorter than expected").into());
                }
                let split_at = data.len() - 2;
                let status = data.split_off(split_at);
                // This will bubble up error if status != no error
                let status = ApduErrorStatus::from([status[0], status[1]]);

                match msg.handle_response_ctap1(status, &data) {
                    Ok(out) => return Ok(out),
                    Err(Retryable::Retry) => {
                        // sleep 100ms then loop again
                        // TODO(baloo): meh, use tokio instead?
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(Retryable::Error(e)) => return Err(e),
                }
            } else {
                return Err(HIDError::UnexpectedCmd(cmd.into()));
            }
        }
    }

    // This is ugly as we have 2 init-functions now, but the fastest way currently.
    fn init(&mut self, nonce: Nonce) -> Result<(), HIDError> {
        let resp = <Self as HIDDevice>::initialize(self, nonce)?;
        // TODO(baloo): this logic should be moved to
        //              transport/mod.rs::Device trait
        if self.supports_ctap2() {
            let command = GetInfo::default();
            let info = self.send_cbor(&command)?;
            debug!("{:?} infos: {:?}", self.id(), info);

            self.set_authenticator_info(info);
        }
        if self.supports_ctap1() {
            let command = GetVersion::default();
            // We don't really use the result here
            self.send_apdu(&command)?;
        }
        Ok(resp)
    }

    fn block_and_blink(&mut self) -> BlinkResult {
        // if let Some(info) = self.get_authenticator_info() {
        //     if info.versions.contains("FIDO_2_1") || info.versions.contains("FIDO_2_1_PRE") { /* TODO: Use blink request */
        //     }
        // } else {
        // We need to fake a blink-request, because FIDO2.0 forgot to specify one
        // See: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#using-pinToken-in-authenticatorMakeCredential
        let mut msg = MakeCredentials::new(
            CollectedClientData {
                webauthn_type: WebauthnType::Create,
                challenge: Challenge::new(vec![0, 1, 2, 3, 4]),
                origin: String::new(),
                cross_origin: false,
                token_binding: None,
            },
            RelyingPartyWrapper::Data(RelyingParty {
                id: String::from("make.me.blink"),
                ..Default::default()
            }),
            Some(User {
                id: vec![0],
                name: Some(String::from("make.me.blink")),
                ..Default::default()
            }),
            vec![PublicKeyCredentialParameters {
                alg: crate::COSEAlgorithm::ES256,
            }],
            vec![],
            MakeCredentialsOptions::default(),
            MakeCredentialsExtensions::default(),
            None,
        );
        // Using a zero-length pinAuth will trigger the device to blink
        // For CTAP1, this gets ignored anyways and we do a 'normal' register
        // command, which also just blinks.
        msg.set_pin_auth(Some(PinAuth::empty_pin_auth()));
        info!("Trying to blink: {:?}", &msg);

        match self.send_msg(&msg) {
            // Spec only says PinInvalid or PinNotSet should be returned on the fake touch-request,
            // but Yubikeys for example return PinAuthInvalid. A successful return is also possible
            // for CTAP1-tokens so we catch those here as well.
            Ok(_)
            | Err(HIDError::Command(CommandError::StatusCode(StatusCode::PinInvalid, _)))
            | Err(HIDError::Command(CommandError::StatusCode(StatusCode::PinAuthInvalid, _)))
            | Err(HIDError::Command(CommandError::StatusCode(StatusCode::PinNotSet, _))) => {
                BlinkResult::DeviceSelected
            }
            // We cancelled the receive, because another device was selected.
            Err(HIDError::Command(CommandError::StatusCode(StatusCode::KeepaliveCancel, _))) => {
                debug!("Device {:?} got cancelled", &self);
                BlinkResult::Cancelled
            }
            // Something unexpected happened, so we assume this device is not usable and interpreting
            // this equivalent to being cancelled.
            e => {
                error!("Device {:?} received unexpected answer, so we assume an error occurred and we are NOT using this device (assuming the request was cancelled): {:?}", &self, e);
                BlinkResult::Cancelled
            }
        }
        // }
    }
    fn supports_ctap1(&self) -> bool {
        // CAPABILITY_NMSG:
        // If set to 1, authenticator DOES NOT implement U2FHID_MSG function
        !self.get_device_info().cap_flags.contains(Capability::NMSG)
    }

    fn supports_ctap2(&self) -> bool {
        self.get_device_info().cap_flags.contains(Capability::CBOR)
    }
}
