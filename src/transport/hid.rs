use crate::consts::{HIDCmd, CID_BROADCAST};
use crate::crypto::ECDHSecret;
use crate::ctap2::commands::get_info::AuthenticatorInfo;
use crate::transport::{errors::HIDError, Nonce};
use crate::u2ftypes::{U2FDevice, U2FDeviceInfo, U2FHIDCont, U2FHIDInit, U2FHIDInitResp};
use rand::{thread_rng, RngCore};
use std::cmp::Eq;
use std::fmt;
use std::hash::Hash;
use std::io;

pub trait HIDDevice
where
    Self: io::Read,
    Self: io::Write,
    Self: U2FDevice,
    Self: Sized,
    Self: fmt::Debug,
{
    type BuildParameters: Sized;
    type Id: fmt::Debug + PartialEq + Eq + Hash + Sized;

    // Open device, verify that it is indeed a CTAP device and potentially read initial values
    fn new(parameters: Self::BuildParameters) -> Result<Self, (HIDError, Self::Id)>;
    fn id(&self) -> Self::Id;
    fn initialized(&self) -> bool;
    // Check if the device is actually a token
    fn is_u2f(&self) -> bool;
    fn get_authenticator_info(&self) -> Option<&AuthenticatorInfo>;
    fn set_authenticator_info(&mut self, authenticator_info: AuthenticatorInfo);
    fn set_shared_secret(&mut self, secret: ECDHSecret);
    fn get_shared_secret(&self) -> Option<&ECDHSecret>;
    fn clone_device_as_write_only(&self) -> Result<Self, HIDError>;

    // Initialize on a protocol-level
    fn initialize(&mut self, noncecmd: Nonce) -> Result<(), HIDError> {
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

    fn sendrecv(&mut self, cmd: HIDCmd, send: &[u8]) -> io::Result<(HIDCmd, Vec<u8>)> {
        let cmd: u8 = cmd.into();
        self.u2f_write(cmd, send)?;
        loop {
            let (cmd, data) = self.u2f_read()?;
            if cmd != HIDCmd::Keepalive {
                break Ok((cmd, data));
            }
        }
    }

    fn u2f_write(&mut self, cmd: u8, send: &[u8]) -> io::Result<()> {
        let mut count = U2FHIDInit::write(self, cmd, send)?;

        // Send continuation packets.
        let mut sequence = 0u8;
        while count < send.len() {
            count += U2FHIDCont::write(self, sequence, &send[count..])?;
            sequence += 1;
        }

        Ok(())
    }

    fn u2f_read(&mut self) -> io::Result<(HIDCmd, Vec<u8>)> {
        // Now we read. This happens in 2 chunks: The initial packet, which has
        // the size we expect overall, then continuation packets, which will
        // fill in data until we have everything.
        let (cmd, data) = {
            let (cmd, mut data) = U2FHIDInit::read(self)?;

            trace!("init frame data read: {:04X?}", &data);
            let mut sequence = 0u8;
            while data.len() < data.capacity() {
                let max = data.capacity() - data.len();
                data.extend_from_slice(&U2FHIDCont::read(self, sequence, max)?);
                sequence += 1;
            }
            (cmd, data)
        };
        trace!("u2f_read({:?}) cmd={:?}: {:04X?}", self.id(), cmd, &data);
        Ok((cmd, data))
    }

    fn cancel(&mut self) -> Result<(), HIDError> {
        let cancel: u8 = HIDCmd::Cancel.into();
        self.u2f_write(cancel, &[])?;
        Ok(())
    }
}
