use pretty_hex::pretty_hex;
use rand::{thread_rng, RngCore};
use std::cmp;
use std::fmt;
use std::io;

use crate::ctap2::commands::{AuthenticatorInfo, ECDHSecret, GetInfo, Request};
use crate::transport::{Error, FidoDevice, ProtocolSupport};
use crate::util::{io_err, trace_hex};

use consts::{
    CONT_DATA_SIZE, CTAPHID_CANCEL, CTAPHID_CBOR, CTAPHID_ERROR, CTAPHID_INIT, CTAPHID_KEEPALIVE,
    CTAPHID_LOCK, CTAPHID_MSG, CTAPHID_PING, CTAPHID_WINK, HID_RPT_SIZE, INIT_DATA_SIZE, TYPE_INIT,
};

pub type Cid = [u8; 4];
pub type DeviceVersion = [u8; 3];

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum HIDCmd {
    Ping,
    Msg,
    Lock,
    Init,
    Wink,
    Cbor,
    Cancel,
    Keepalive,
    Error,
    Unknown(u8),
}

impl Into<u8> for HIDCmd {
    fn into(self) -> u8 {
        match self {
            HIDCmd::Ping => CTAPHID_PING,
            HIDCmd::Msg => CTAPHID_MSG,
            HIDCmd::Lock => CTAPHID_LOCK,
            HIDCmd::Init => CTAPHID_INIT,
            HIDCmd::Wink => CTAPHID_WINK,
            HIDCmd::Cbor => CTAPHID_CBOR,
            HIDCmd::Cancel => CTAPHID_CANCEL,
            HIDCmd::Keepalive => CTAPHID_KEEPALIVE,
            HIDCmd::Error => CTAPHID_ERROR,
            HIDCmd::Unknown(v) => v,
        }
    }
}

impl From<u8> for HIDCmd {
    fn from(v: u8) -> HIDCmd {
        match v {
            CTAPHID_PING => HIDCmd::Ping,
            CTAPHID_MSG => HIDCmd::Msg,
            CTAPHID_LOCK => HIDCmd::Lock,
            CTAPHID_INIT => HIDCmd::Init,
            CTAPHID_WINK => HIDCmd::Wink,
            CTAPHID_CBOR => HIDCmd::Cbor,
            CTAPHID_CANCEL => HIDCmd::Cancel,
            CTAPHID_KEEPALIVE => HIDCmd::Keepalive,
            CTAPHID_ERROR => HIDCmd::Error,
            v => HIDCmd::Unknown(v),
        }
    }
}

bitflags! {
    pub struct Capability: u8 {
        const WINK = 0x01;
        const LOCK = 0x02;
        const CBOR = 0x04;
        const NMSG = 0x08;
    }
}

impl Capability {
    pub fn has_fido2(self) -> bool {
        self.intersects(Capability::CBOR)
    }
}

pub trait HIDDevice
where
    Self: io::Read,
    Self: io::Write,
    Self: Sized,
{
    type BuildParameters;
    type Id: fmt::Debug;

    fn new(parameters: Self::BuildParameters) -> Result<Self, Error>
    where
        Self::BuildParameters: Sized,
        Self: Sized;

    fn initialized(&self) -> bool;
    fn initialize(&mut self);

    fn id(&self) -> Self::Id;

    // CID describes channel id, this is USBHID specific, this allows multiple
    // clients to talk to the same authenticator
    fn cid(&self) -> &Cid;
    fn set_cid(&mut self, cid: Cid);

    fn u2fhid_version(&self) -> u8;
    fn set_u2fhid_version(&mut self, version: u8);

    // The meaning and interpretation of the device version number is vendor
    // defined.
    fn device_version(&self) -> &DeviceVersion;
    fn set_device_version(&mut self, device_version: DeviceVersion);

    fn capabilities(&self) -> Capability;
    fn set_capabilities(&mut self, capabilities: Capability);

    fn protocol_support(&self) -> ProtocolSupport {
        let mut support = ProtocolSupport::FIDO1;

        if self.capabilities().intersects(Capability::CBOR) {
            support |= ProtocolSupport::FIDO2;
        }
        if self.u2fhid_version() >= 2 && !self.capabilities().intersects(Capability::NMSG) {
            // CAPABILITY_NMSG:
            //   If set to 1, authenticator DOES NOT implement CTAPHID_MSG function
            support &= !ProtocolSupport::FIDO1;
        }

        support
    }

    fn shared_secret(&self) -> Option<&ECDHSecret>;
    fn set_shared_secret(&mut self, secret: ECDHSecret);

    fn authenticator_info(&self) -> Option<&AuthenticatorInfo>;
    fn set_authenticator_info(&mut self, authenticator_info: AuthenticatorInfo);

    fn init(&mut self) -> Result<(), Error>
    where
        Self::Id: fmt::Debug,
    {
        if self.initialized() {
            return Ok(());
        }

        let mut nonce = [0u8; 8];
        thread_rng().fill_bytes(&mut nonce);

        let (cmd, r) = self.sendrecv(HIDCmd::Init, &nonce[..])?;
        if cmd != HIDCmd::Init {
            return Err(Error::DeviceError);
        }
        if r.len() < 17 {
            return Err(Error::UnexpectedInitReplyLen);
        }
        if r[0..8] != nonce {
            return Err(Error::NonceMismatch);
        }

        let mut cid = [0u8; 4];
        cid[..].copy_from_slice(&r[8..12]);
        self.set_cid(cid);
        self.set_u2fhid_version(r[12]);

        let mut device_version = [0u8; 3];
        device_version[..].copy_from_slice(&r[13..16]);
        self.set_device_version(device_version);
        let capabilities = Capability::from_bits_truncate(r[16]);
        self.set_capabilities(capabilities);

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
        self.u2f_write(TYPE_INIT | cmd, send)?;
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
        let cid = *self.cid();
        trace!("u2f_write({:?}): {}", self.id(), pretty_hex(&send));
        let mut inner = U2FHid { dev: self, cid };

        // Send initialization packet.
        let mut count = inner.init_write(cmd, send)?;

        // Send continuation packets.
        let mut sequence = 0u8;
        while count < send.len() {
            count += inner.cont_write(sequence, &send[count..])?;
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
        let cid: Cid = *self.cid();
        let (cmd, data) = {
            let mut inner = U2FHid { dev: self, cid };

            let (cmd, mut data) = inner.init_read()?;

            let mut sequence = 0u8;
            while data.len() < data.capacity() {
                let max = data.capacity() - data.len();
                data.extend_from_slice(&inner.cont_read(sequence, max)?);
                sequence += 1;
            }
            (cmd, data)
        };

        trace!(
            "u2f_read({:?}) cmd={:?}: {}",
            self.id(),
            cmd,
            pretty_hex(&&data[..])
        );
        Ok((cmd, data))
    }
}

impl<T> FidoDevice for T
where
    T: HIDDevice,
    T: fmt::Debug,
    <T as HIDDevice>::Id: fmt::Debug,
{
    type BuildParameters = <Self as HIDDevice>::BuildParameters;

    fn send_cbor<'msg, Req: Request>(&mut self, msg: &'msg Req) -> Result<Req::Output, Error> {
        debug!("sending {:?} to {:?}", msg, self);

        let mut buf: Vec<u8> = Vec::new();
        let mut data = msg.wire_format(self)?;
        // CTAP2 command
        buf.push(Req::command() as u8);
        // payload
        buf.append(&mut data);
        let buf = buf;

        let (cmd, resp) = self.sendrecv(HIDCmd::Cbor, &buf[..])?;
        debug!("got from {:?} status={:?}: {:?}", self, cmd, resp);
        if cmd == HIDCmd::Cbor {
            Ok(msg.parse_response(&resp[..])?)
        } else {
            Err(Error::UnexpectedStatus(cmd.into()))
        }
    }

    fn send_apdu<'msg, Req: Request>(&mut self, _msg: &'msg Req) -> Result<Req::Output, Error> {
        unimplemented!("apdu support not yet implemented");
    }

    fn new(parameters: Self::BuildParameters) -> Result<Self, Error>
    where
        Self::BuildParameters: Sized,
        Self: Sized,
    {
        <Self as HIDDevice>::new(parameters)
    }

    fn init(&mut self) -> Result<(), Error> {
        let resp = <Self as HIDDevice>::init(self);

        // TODO(baloo): this logic should be moved to
        //              transport/mod.rs::Device trait
        if self.capabilities().has_fido2() {
            let command = GetInfo::default();
            let info = self.send_cbor(&command)?;
            debug!("{:?} infos: {:?}", self.id(), info);

            self.set_authenticator_info(info);
        }

        self.initialize();
        resp
    }

    fn initialized(&self) -> bool {
        <Self as HIDDevice>::initialized(self)
    }

    fn initialize(&mut self) {
        <Self as HIDDevice>::initialize(self);
    }

    fn protocol_support(&self) -> ProtocolSupport {
        <Self as HIDDevice>::protocol_support(self)
    }

    fn set_shared_secret(&mut self, secret: ECDHSecret) {
        <Self as HIDDevice>::set_shared_secret(self, secret)
    }

    fn shared_secret(&self) -> Option<&ECDHSecret> {
        <Self as HIDDevice>::shared_secret(self)
    }

    fn set_authenticator_info(&mut self, authenticator_info: AuthenticatorInfo) {
        <Self as HIDDevice>::set_authenticator_info(self, authenticator_info)
    }

    fn authenticator_info(&self) -> Option<&AuthenticatorInfo> {
        <Self as HIDDevice>::authenticator_info(self)
    }
}

struct U2FHid<'dev, T> {
    dev: &'dev mut T,
    cid: Cid,
}

impl<'dev, T> U2FHid<'dev, T>
where
    T: io::Read + io::Write,
{
    // Init structure for U2F Communications. Tells the receiver what channel
    // communication is happening on, what command is running, and how much data
    // to expect to receive over all.
    //
    // Spec at https://fidoalliance.org/specs/fido-u2f-v1.
    // 0-nfc-bt-amendment-20150514/fido-u2f-hid-protocol.html#message--and-packet-structure
    fn init_read(&mut self) -> io::Result<(HIDCmd, Vec<u8>)> {
        let mut frame = [0u8; HID_RPT_SIZE];
        let count = self.dev.read(&mut frame)?;
        trace!("init frame read: {}", pretty_hex(&&frame[..]));

        if count != HID_RPT_SIZE {
            return Err(io_err("invalid init packet"));
        }

        if self.cid[..] != frame[..4] {
            return Err(io_err("invalid channel id"));
        }

        let cmd = HIDCmd::from(frame[4]);
        let cap = (frame[5] as usize) << 8 | (frame[6] as usize);
        let mut data = Vec::with_capacity(cap);

        let len = cmp::min(cap, INIT_DATA_SIZE);
        data.extend_from_slice(&frame[7..7 + len]);

        trace!("init frame data read: {}", pretty_hex(&&data[..]));
        Ok((cmd, data))
    }

    fn init_write(&mut self, cmd: u8, data: &[u8]) -> io::Result<usize> {
        if data.len() > 0xffff {
            return Err(io_err("payload length > 2^16"));
        }

        let mut frame = [0; HID_RPT_SIZE + 1];
        // TODO(baloo): there is a required [0] byte preprend on the frame.
        //              I'm not sure why, will have to ask J.C.J.
        //              I'd like to document it.
        frame[1..5].copy_from_slice(&self.cid[..]);
        frame[5] = cmd;
        frame[6] = (data.len() >> 8) as u8;
        frame[7] = data.len() as u8;

        let count = cmp::min(data.len(), INIT_DATA_SIZE);
        frame[8..8 + count].copy_from_slice(&data[..count]);
        trace_hex(&frame);

        trace!("init frame write: {}", pretty_hex(&&frame[..]));
        if self.dev.write(&frame)? != frame.len() {
            return Err(io_err("device write failed"));
        }

        Ok(count)
    }

    // Continuation structure for U2F Communications. After an Init structure is
    // sent, continuation structures are used to transmit all extra data that
    // wouldn't fit in the initial packet. The sequence number increases with
    // every packet, until all data is received.
    //
    // https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-hid-protocol.
    // html#message--and-packet-structure
    fn cont_read(&mut self, seq: u8, max: usize) -> io::Result<Vec<u8>> {
        let mut frame = [0u8; HID_RPT_SIZE];
        let count = self.dev.read(&mut frame)?;

        if count != HID_RPT_SIZE {
            return Err(io_err("invalid cont packet"));
        }

        if self.cid[..] != frame[..4] {
            return Err(io_err("invalid channel id"));
        }

        if seq != frame[4] {
            return Err(io_err("invalid sequence number"));
        }

        let max = cmp::min(max, CONT_DATA_SIZE);
        trace!(
            "cont frame({}) read: {}",
            seq,
            pretty_hex(&&frame[5..5 + max])
        );
        Ok(frame[5..5 + max].to_vec())
    }

    fn cont_write(&mut self, seq: u8, data: &[u8]) -> io::Result<usize> {
        let mut frame = [0; HID_RPT_SIZE + 1];
        // TODO(baloo): there is a required [0] byte preprend on the frame.
        //              I'm not sure why, will have to ask J.C.J
        //              I'd like to document it.
        frame[1..5].copy_from_slice(&self.cid[..]);
        frame[5] = seq;

        let count = cmp::min(data.len(), CONT_DATA_SIZE);
        frame[6..6 + count].copy_from_slice(&data[..count]);
        trace!("cont frame({}) write: {}", seq, pretty_hex(&&frame[..]));

        if self.dev.write(&frame)? != frame.len() {
            return Err(io_err("device write failed"));
        }

        Ok(count)
    }
}
