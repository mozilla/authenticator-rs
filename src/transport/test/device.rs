/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate libc;

use std::fmt;
use std::io;

use super::TestCase;
use consts::CID_BROADCAST;
use ctap2::commands::{AuthenticatorInfo, ECDHSecret};
use transport::hid::{Capability, Cid, DeviceVersion, HIDDevice};
use transport::Error;

#[derive(Debug)]
pub struct Device {
    test_case: TestCase,
    inner: Box<TestDevice>,
    initialized: bool,
    cid: Cid,
    u2fhid_version: u8,
    device_version: DeviceVersion,
    capability: Capability,
    authenticator_info: Option<AuthenticatorInfo>,
    shared_secret: Option<ECDHSecret>,
}

impl PartialEq for Device {
    fn eq(&self, other: &Device) -> bool {
        self.test_case == other.test_case
    }
}

impl io::Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl io::Write for Device {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl HIDDevice for Device {
    type BuildParameters = TestCase;
    type Id = TestCase;

    fn new(test_case: TestCase) -> Result<Self, Error> {
        debug!("test_case={:?}", test_case);
        let inner: Box<TestDevice> = match test_case {
            TestCase::WriteError => Box::new(write_error::WriteErrorDevice::default()),
            TestCase::Fido2Simple => Box::new(fido2simple::Fido2SimpleDevice::default()),
        };

        Ok(Self {
            test_case,
            inner,
            initialized: false,
            cid: CID_BROADCAST,
            u2fhid_version: 0,
            device_version: [0u8; 3],
            capability: Capability::empty(),
            authenticator_info: None,
            shared_secret: None,
        })
    }

    fn id(&self) -> Self::Id {
        self.test_case
    }

    fn initialized(&self) -> bool {
        self.initialized
    }

    fn initialize(&mut self) {
        self.initialized = true;
    }

    fn cid(&self) -> &Cid {
        &self.cid
    }

    fn set_cid(&mut self, cid: Cid) {
        self.cid = cid;
    }

    fn u2fhid_version(&self) -> u8 {
        self.u2fhid_version
    }

    fn set_u2fhid_version(&mut self, version: u8) {
        self.u2fhid_version = version;
    }

    fn device_version(&self) -> &DeviceVersion {
        &self.device_version
    }

    fn set_device_version(&mut self, device_version: DeviceVersion) {
        self.device_version = device_version;
    }

    fn capabilities(&self) -> Capability {
        self.capability
    }

    fn set_capabilities(&mut self, capabilities: Capability) {
        self.capability = capabilities;
    }

    fn shared_secret(&self) -> Option<&ECDHSecret> {
        self.shared_secret.as_ref()
    }
    fn set_shared_secret(&mut self, secret: ECDHSecret) {
        self.shared_secret = Some(secret)
    }

    fn authenticator_info(&self) -> Option<&AuthenticatorInfo> {
        self.authenticator_info.as_ref()
    }
    fn set_authenticator_info(&mut self, authenticator_info: AuthenticatorInfo) {
        self.authenticator_info = Some(authenticator_info)
    }
}

trait TestDevice: io::Read + io::Write + fmt::Debug {}

mod write_error {
    use super::TestDevice;
    use std::io;

    #[derive(Debug)]
    pub struct WriteErrorDevice;

    impl Default for WriteErrorDevice {
        fn default() -> Self {
            WriteErrorDevice
        }
    }

    impl io::Read for WriteErrorDevice {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Other, "oh no!"))
        }
    }

    impl io::Write for WriteErrorDevice {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Other, "oh no!"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "oh no!"))
        }
    }

    impl TestDevice for WriteErrorDevice {}
}

mod fido2simple {
    use std::cmp::min;
    use std::io::{self, Read, Write};
    use std::mem;

    use byteorder::{BigEndian, ByteOrder};
    use pretty_hex::pretty_hex;
    use rand::{thread_rng, RngCore};
    use serde_cbor::from_slice;

    use crate::consts::{CTAPHID_INIT, HID_RPT_SIZE};
    use crate::ctap2::attestation::{
        AAGuid, AttestationObject, AttestationStatement, AttestedCredentialData, AuthenticatorData,
        AuthenticatorDataFlags,
    };
    use crate::ctap2::commands::test::AUTHENTICATOR_INFO_PAYLOAD;
    use crate::ctap2::commands::{Command, StatusCode};
    use crate::transport::hid::{Capability, HIDCmd};

    use super::TestDevice;
    use crate::transport::platform::commands::MakeCredentials;
    use crate::transport::platform::crypto::{Error, PrivateKey};

    #[derive(Debug)]
    enum FidoStateInternal {
        PendingReply { reply: Vec<u8> },
        Ready,
        Working,
    }

    #[derive(Debug)]
    struct FidoState {
        state: FidoStateInternal,
        private_key: PrivateKey,
    }

    impl FidoState {
        fn new() -> Result<Self, Error> {
            let private_key = PrivateKey::generate()?;
            Ok(FidoState {
                state: FidoStateInternal::Ready,
                private_key,
            })
        }

        fn read(&mut self) -> io::Result<Vec<u8>> {
            match mem::replace(&mut self.state, FidoStateInternal::Working) {
                FidoStateInternal::PendingReply{reply} => {
                    mem::replace(&mut self.state, FidoStateInternal::Ready);
                    Ok(reply)
                },
                FidoStateInternal::Ready{..} => Err(io::Error::new(io::ErrorKind::Other, "you forgot to send a command, but let me tell you a little story: Once upon a time, a fido2 device ...")),
                FidoStateInternal::Working => Err(io::Error::new(io::ErrorKind::Other, "oh no! this should not happen, you have a bug in your logic :( (read(FidoStateInternal::Working))"))
            }
        }

        fn write_cbor(&mut self, data: &[u8]) -> io::Result<usize> {
            trace!("reading cbor input: {}", pretty_hex(&data));
            let mut buff = io::Cursor::new(data);

            match mem::replace(&mut self.state, FidoStateInternal::Working) {
                FidoStateInternal::Ready => {
                    let mut cbor_cmd  = [0u8; 1];
                    if buff.read(&mut cbor_cmd)? != 1 {
                        return Err(io::Error::new(io::ErrorKind::Other, "expected cbor cmd"));
                    }
                    let cbor_cmd = cbor_cmd[0];
                    let len = buff.get_ref().len() - 1;
                    let mut args = Vec::with_capacity(len);
                    args.resize(len, 0);
                    if buff.read(args.as_mut_slice())? != len {
                        return Err(io::Error::new(io::ErrorKind::Other, "unable to read args"));
                    }

                    let cbor_cmd = if let Some(cmd) = Command::from_u8(cbor_cmd) {
                        cmd
                    } else {
                        return Err(io::Error::new(io::ErrorKind::Other, format!("unknown cbor command: {:?}", cbor_cmd)));
                    };

                    trace!("got CBOR({:?}): {}", cbor_cmd, pretty_hex(&&args));
                    match cbor_cmd {
                        Command::GetInfo => {
                            // Prepare reply
                            let mut reply = io::Cursor::new(Vec::new());
                            reply.write_all(&[StatusCode::OK.into()])?;
                            reply.write_all(&AUTHENTICATOR_INFO_PAYLOAD[..])?;

                            reply.set_position(0);
                            let reply = reply.into_inner();
                            trace!("replying: {}", pretty_hex(&&reply[..]));
                            mem::replace(&mut self.state, FidoStateInternal::PendingReply{
                                reply,
                            });
                        },
                        Command::MakeCredentials => {
                            let params: MakeCredentials = from_slice(&args[..])
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("parse error: {:?}", e)))?;
                            debug!("MakeCredentials: {:?}", params);

                            let credential_data = AttestedCredentialData {
                                aaguid: AAGuid([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]),
                                credential_id: vec![],
                                credential_public_key: self.private_key.public_key(),
                            };
                            let auth_data = AuthenticatorData {
                                rp_id_hash: params.rp().hash(),
                                counter: 0,
                                flags: AuthenticatorDataFlags::empty(),
                                extensions: vec![],
                                credential_data: Some(credential_data),
                            };
                            let att_statement = AttestationStatement::None;
                            let attestation_object = AttestationObject {
                                auth_data,
                                att_statement,
                            };

                            let mut reply = io::Cursor::new(Vec::new());
                            reply.write_all(&[StatusCode::OK.into()])?;
                            let data = serde_cbor::to_vec(&attestation_object)
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("error serializing: {:?}", e)))?;
                            reply.write_all(&data[..])?;

                            reply.set_position(0);
                            let reply = reply.into_inner();
                            trace!("replying: {}", pretty_hex(&&reply[..]));
                            mem::replace(&mut self.state, FidoStateInternal::PendingReply{
                                reply,
                            });
                        }
                        _ => {
                        }
                    }

                    let buf = buff.into_inner();
                    Ok(buf.len())
                },

                FidoStateInternal::PendingReply{..} => Err(io::Error::new(io::ErrorKind::Other, "oh no! this should not happen, you have a bug in your logic :(, write(FidoStateInternal::PendingReply)")),
                FidoStateInternal::Working => Err(io::Error::new(io::ErrorKind::Other, "oh no! this should not happen, you have a bug in your logic :( (Write(FidoStateInternal::Working)")),
            }
        }
    }

    #[derive(Debug)]
    enum HIDState {
        Uninitialized,
        PendingReply {
            cid: [u8; 4],
            next_cid: Option<[u8; 4]>,
            hid_cmd: HIDCmd,
            reply: io::Cursor<Vec<u8>>,
            seq: u8,
            fido_state: Option<FidoState>,
        },
        PendingRequest {
            cid: [u8; 4],
            data_len: u16,
            request: Vec<u8>,
            seq: u8,
            fido_state: FidoState,
        },
        Ready {
            cid: [u8; 4],
            fido_state: FidoState,
        },
        Working,
    }

    #[derive(Debug)]
    pub struct Fido2SimpleDevice {
        state: HIDState,
    }

    impl Default for Fido2SimpleDevice {
        fn default() -> Self {
            Fido2SimpleDevice {
                state: HIDState::Uninitialized,
            }
        }
    }

    const HID_HEADER_SIZE: usize = 4;

    impl io::Read for Fido2SimpleDevice {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut buff = io::Cursor::new(buf);
            match mem::replace(&mut self.state, HIDState::Working) {
                HIDState::PendingReply{cid, next_cid, hid_cmd, mut reply, mut seq, fido_state} => {
                    if buff.get_ref().len() < HID_HEADER_SIZE {
                        return Err(io::Error::new(io::ErrorKind::Other, "take a blue pill and enlarge your buffer"));
                    }

                    let my_cid = next_cid.as_ref().unwrap_or(&cid);
                    buff.write_all(my_cid)?;

                    if reply.position() == 0 {
                        // Init packet
                        buff.write_all(&[hid_cmd.into()])?;

                        let len = reply.get_ref().len();
                        let mut len_buf = [0u8; 2];
                        BigEndian::write_u16(&mut len_buf, len as u16);
                        buff.write_all(&len_buf)?;

                        let mut buffer = [0u8; HID_RPT_SIZE - HID_HEADER_SIZE - 1 - 2];
                        reply.read(&mut buffer)?;
                        buff.write_all(&buffer[..])?;
                    } else {
                        // Cont packet
                        buff.write_all(&[seq])?;
                        seq = seq +1;

                        let mut buffer = [0u8; HID_RPT_SIZE - HID_HEADER_SIZE - 1];
                        reply.read(&mut buffer)?;
                        buff.write_all(&buffer[..])?;
                    }

                    if (reply.position() as usize) < reply.get_ref().len() {
                        // we still have data in buffer, need a continuation packet
                        mem::replace(&mut self.state, HIDState::PendingReply {
                            cid,
                            next_cid,
                            hid_cmd,
                            reply,
                            seq,
                            fido_state,
                        });
                    } else {
                        // Note(baloo): unwrap, in tests? not sure we care
                        let fido_state = fido_state.unwrap_or(FidoState::new().unwrap());
                        mem::replace(&mut self.state, HIDState::Ready{cid, fido_state});
                    }

                    // Hackish but meh
                    Ok(HID_RPT_SIZE)
                },
                HIDState::Ready{..} => Err(io::Error::new(io::ErrorKind::Other, "you forgot to send a command, but let me tell you a little story: Once upon a time, a fido2 device ...")),
                HIDState::PendingRequest{..} => Err(io::Error::new(io::ErrorKind::Other, "you haven't finished your sentense")),
                HIDState::Uninitialized => Err(io::Error::new(io::ErrorKind::Other, "do you really think I want to talk to you?")),
                HIDState::Working => Err(io::Error::new(io::ErrorKind::Other, "oh no! this should not happen, you have a bug in your logic :( (read(HIDState::Working))"))
            }
        }
    }

    impl io::Write for Fido2SimpleDevice {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            trace!("reading input: {}", pretty_hex(&buf));
            let mut buff = io::Cursor::new(buf);

            // Unknown HID prefix
            let mut unknown = [0u8; 1];
            if let Ok(l) = buff.read(&mut unknown) {
                if l != 1 {
                    return Err(io::Error::new(io::ErrorKind::Other, "Expected HID prefix"));
                }
            }

            match mem::replace(&mut self.state, HIDState::Working) {
                HIDState::Uninitialized => {
                    let mut broadcast = [0u8; 4];
                    let _ = buff.read(&mut broadcast);
                    if broadcast != [255u8; 4] {
                        return Err(io::Error::new(io::ErrorKind::Other, "Expected hid broadcast"));
                    }

                    let mut command = [0u8; 1];
                    if buff.read(&mut command)? != 1 && command[0] != CTAPHID_INIT {
                        return Err(io::Error::new(io::ErrorKind::Other, "Expected hid init cmd"));
                    }

                    let mut data_len = [0u8; 2];
                    if buff.read(&mut data_len)? != 2 {
                        return Err(io::Error::new(io::ErrorKind::Other, "Expected hid data len"));
                    }

                    let mut nonce = [0u8; 8];
                    if buff.read(&mut nonce)? != 8 {
                        return Err(io::Error::new(io::ErrorKind::Other, "Expected hid nonce"));
                    }

                    let mut cid = [0u8; 4];
                    thread_rng().fill_bytes(&mut cid);
                    let read_buf = buff.into_inner();

                    // Prepare reply
                    let mut reply = io::Cursor::new(Vec::new());

                    reply.write_all(&nonce)?;
                    reply.write_all(&cid)?;
                    // u2fhid version
                    reply.write_all(&[42])?; // I (baloo) have no idea what this is used for
                    // device version
                    reply.write_all(b"\x00\x00\x2a")?;
                    // capabilities
                    reply.write_all(&[Capability::CBOR.bits()])?;
                    reply.set_position(0);

                    let next_cid = Some([255u8; 4]);
                    let hid_cmd = HIDCmd::Init;
                    let seq = 0;
                    let fido_state = None;
                    mem::replace(&mut self.state, HIDState::PendingReply{
                        cid,
                        next_cid,
                        hid_cmd,
                        reply,
                        seq,
                        fido_state,
                    });

                    Ok(read_buf.len())
                },

                HIDState::Ready{cid, mut fido_state} => {
                    let mut command_cid = [0u8; 4];
                    if 4 != buff.read(&mut command_cid)? || command_cid != cid {
                        return Err(io::Error::new(io::ErrorKind::Other, "unexpected cid"));
                    }

                    let mut command = [0u8; 1];
                    buff.read_exact(&mut command).map_err(|_|
                        io::Error::new(io::ErrorKind::Other, "expected hid cmd")
                    )?;

                    match HIDCmd::from(command[0]) {
                        HIDCmd::Cbor => {
                            let mut data_len  = [0u8; 2];
                            buff.read_exact(&mut data_len).map_err(|_|
                                io::Error::new(io::ErrorKind::Other, "expected data_len")
                            )?;

                            let data_len = BigEndian::read_u16(&data_len);

                            let available = min(buff.get_ref().len() - (buff.position() as usize), data_len as usize);
                            let mut request = Vec::with_capacity(data_len as usize);
                            request.resize(available as usize, 0);
                            buff.read_exact(&mut request[..available])?;

                            if (data_len as usize) > available {
                                let new_state = HIDState::PendingRequest{
                                    cid,
                                    fido_state,
                                    seq: 0,
                                    request,
                                    data_len,
                                };

                                mem::replace(&mut self.state, new_state);
                            } else {
                                fido_state.write_cbor(&request[..])?;
                                let reply = fido_state.read()?;

                                let new_state = HIDState::PendingReply{
                                    cid,
                                    next_cid: None,
                                    hid_cmd: HIDCmd::Cbor,
                                    seq: 0,
                                    fido_state: Some(fido_state),
                                    reply: io::Cursor::new(reply),
                                };

                                mem::replace(&mut self.state, new_state);
                            }
                        },
                        _ => unimplemented!("command {:?} is not implemented", command),
                    }

                    let buf = buff.into_inner();
                    Ok(buf.len())
                },
                HIDState::PendingRequest {cid, data_len, mut request, mut seq, mut fido_state} => {
                    let mut command_cid = [0u8; 4];
                    if 4 != buff.read(&mut command_cid)? || command_cid != cid {
                        return Err(io::Error::new(io::ErrorKind::Other, "unexpected cid"));
                    }
                    let mut seq_ = [0u8; 1];
                    buff.read_exact(&mut seq_)?;
                    if seq_[0] != seq {
                        return Err(io::Error::new(io::ErrorKind::Other, "unexpected sequence"));
                    }
                    seq = seq + 1;

                    let available = min(buff.get_ref().len() - (buff.position() as usize), (data_len as usize) - request.len());

                    let mut cont_buf = Vec::with_capacity(available);
                    cont_buf.resize(available, 0);
                    buff.read_exact(&mut cont_buf[..])?;
                    debug!("PendingRequest:\nbuf = {}\ncont = {}", pretty_hex(&&request[..]), pretty_hex(&&cont_buf[..]));
                    request.append(&mut cont_buf);

                    if (data_len as usize) == request.len() {
                        fido_state.write_cbor(&request[..])?;
                        let reply = fido_state.read()?;

                        let new_state = HIDState::PendingReply{
                            cid,
                            next_cid: None,
                            hid_cmd: HIDCmd::Cbor,
                            seq: 0,
                            fido_state: Some(fido_state),
                            reply: io::Cursor::new(reply),
                        };

                        mem::replace(&mut self.state, new_state);
                    } else {
                        let new_state = HIDState::PendingRequest{
                            cid,
                            fido_state,
                            seq,
                            request,
                            data_len,
                        };

                        mem::replace(&mut self.state, new_state);
                    }
                    let buf = buff.into_inner();
                    Ok(buf.len())
                },
                HIDState::PendingReply{..} => Err(io::Error::new(io::ErrorKind::Other, "oh no! this should not happen, you have a bug in your logic :(, write(HIDState::PendingReply)")),
                HIDState::Working => Err(io::Error::new(io::ErrorKind::Other, "oh no! this should not happen, you have a bug in your logic :( (Write(HIDState::Working)")),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            // nothing?
            Ok(())
        }
    }

    impl TestDevice for Fido2SimpleDevice {}
}
