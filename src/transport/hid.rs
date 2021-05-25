use crate::consts::{HIDCmd, CID_BROADCAST};
use crate::ctap2::commands::get_info::{AuthenticatorInfo, GetInfo};
use crate::ctap2::commands::get_version::GetVersion;
use crate::ctap2::commands::{RequestCtap1, RequestCtap2, Retryable};
use crate::ctap2::crypto::ECDHSecret;
use crate::transport::{
    errors::{ApduErrorStatus, HIDError},
    FidoDevice, Nonce,
};
use crate::u2ftypes::{U2FDevice, U2FDeviceInfo, U2FHIDCont, U2FHIDInit, U2FHIDInitResp};
use crate::util::io_err;
use rand::{thread_rng, RngCore};
use std::fmt;
use std::io;
use std::thread;
use std::time::Duration;

pub trait HIDDevice
where
    Self: io::Read,
    Self: io::Write,
    Self: U2FDevice,
    Self: Sized,
{
    type BuildParameters;
    type Id: fmt::Debug;

    fn new(parameters: Self::BuildParameters) -> Result<Self, HIDError>
    where
        Self::BuildParameters: Sized,
        Self: Sized;

    fn initialized(&self) -> bool;

    fn id(&self) -> Self::Id;

    fn get_authenticator_info(&self) -> Option<&AuthenticatorInfo>;
    fn set_authenticator_info(&mut self, authenticator_info: AuthenticatorInfo);
    fn set_shared_secret(&mut self, secret: ECDHSecret);
    fn get_shared_secret(&self) -> Option<&ECDHSecret>;

    fn initialize(&mut self, noncecmd: Nonce) -> Result<(), HIDError>
    where
        Self::Id: fmt::Debug,
    {
        if self.initialized() {
            return Ok(());
        }

        let nonce = match noncecmd {
            Nonce::Use(x) => x,
            Nonce::CreateRandom => {
                let mut nonce = [0u8; 8];
                thread_rng().fill_bytes(&mut nonce);
                nonce
            }
        };

        // Send Init to broadcast address to create a new channel
        self.set_cid(CID_BROADCAST);
        let (cmd, raw) = self.sendrecv(HIDCmd::Init, &nonce)?;
        if cmd != HIDCmd::Init {
            return Err(HIDError::DeviceError);
        }

        let rsp = U2FHIDInitResp::read(&raw, &nonce)?;

        // Get the new Channel ID
        self.set_cid(rsp.cid);

        let vendor = self
            .get_property("Manufacturer")
            .unwrap_or_else(|_| String::from("Unknown Vendor"));
        let product = self
            .get_property("Product")
            .unwrap_or_else(|_| String::from("Unknown Device"));

        self.set_device_info(U2FDeviceInfo {
            vendor_name: vendor.as_bytes().to_vec(),
            device_name: product.as_bytes().to_vec(),
            version_interface: rsp.version_interface,
            version_major: rsp.version_major,
            version_minor: rsp.version_minor,
            version_build: rsp.version_build,
            cap_flags: rsp.cap_flags,
        });

        // A CTAPHID host SHALL accept a response size that is longer than the
        // anticipated size to allow for future extensions of the protocol, yet
        // maintaining backwards compatibility. Future versions will maintain
        // the response structure of the current version, but additional fields
        // may be added.

        Ok(())
    }

    fn sendrecv(&mut self, cmd: HIDCmd, send: &[u8]) -> io::Result<(HIDCmd, Vec<u8>)>
    where
        Self::Id: fmt::Debug,
    {
        let cmd: u8 = cmd.into();
        self.u2f_write(cmd, send)?;
        loop {
            let (cmd, data) = self.u2f_read()?;
            if cmd != HIDCmd::Keepalive {
                break Ok((cmd, data));
            }
        }
    }

    fn u2f_write(&mut self, cmd: u8, send: &[u8]) -> io::Result<()>
    where
        Self::Id: fmt::Debug,
    {
        let mut count = U2FHIDInit::write(self, cmd, send)?;

        // Send continuation packets.
        let mut sequence = 0u8;
        while count < send.len() {
            count += U2FHIDCont::write(self, sequence, &send[count..])?;
            sequence += 1;
        }

        Ok(())
    }

    fn u2f_read(&mut self) -> io::Result<(HIDCmd, Vec<u8>)>
    where
        Self::Id: fmt::Debug,
    {
        // Now we read. This happens in 2 chunks: The initial packet, which has
        // the size we expect overall, then continuation packets, which will
        // fill in data until we have everything.
        let (cmd, data) = {
            let (cmd, mut data) = U2FHIDInit::read(self)?;

            trace!("init frame data read: {:#04X?}", &data);
            let mut sequence = 0u8;
            while data.len() < data.capacity() {
                let max = data.capacity() - data.len();
                data.extend_from_slice(&U2FHIDCont::read(self, sequence, max)?);
                sequence += 1;
            }
            (cmd, data)
        };
        trace!("u2f_read({:?}) cmd={:?}: {:#04X?}", self.id(), cmd, &data);
        Ok((cmd, data))
    }
}

impl<T> FidoDevice for T
where
    T: HIDDevice + U2FDevice + fmt::Debug,
    <T as HIDDevice>::Id: fmt::Debug,
{
    type BuildParameters = <Self as HIDDevice>::BuildParameters;

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

    fn new(parameters: Self::BuildParameters) -> Result<Self, HIDError>
    where
        Self::BuildParameters: Sized,
        Self: Sized,
    {
        <Self as HIDDevice>::new(parameters)
    }

    fn init(&mut self, nonce: Nonce) -> Result<(), HIDError> {
        let resp = <Self as HIDDevice>::initialize(self, nonce);
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
        resp
    }

    fn initialized(&self) -> bool {
        <Self as HIDDevice>::initialized(self)
    }

    fn set_authenticator_info(&mut self, authenticator_info: AuthenticatorInfo) {
        <Self as HIDDevice>::set_authenticator_info(self, authenticator_info)
    }

    fn get_authenticator_info(&self) -> Option<&AuthenticatorInfo> {
        <Self as HIDDevice>::get_authenticator_info(self)
    }

    fn set_shared_secret(&mut self, shared_secret: ECDHSecret) {
        <Self as HIDDevice>::set_shared_secret(self, shared_secret)
    }

    fn get_shared_secret(&self) -> Option<&ECDHSecret> {
        <Self as HIDDevice>::get_shared_secret(self)
    }
}
