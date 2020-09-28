/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::CString;
use std::io;

use crate::consts::*;
use crate::util::io_err;

pub trait APDUDevice {
    fn init_apdu(&mut self) -> io::Result<()>;
    fn send_apdu(&mut self, cmd: u8, p1: u8, send: &[u8]) -> io::Result<(Vec<u8>, [u8; 2])>;
}

////////////////////////////////////////////////////////////////////////
// Device Commands
////////////////////////////////////////////////////////////////////////

pub fn apdu_register<T>(dev: &mut T, challenge: &[u8], application: &[u8]) -> io::Result<Vec<u8>>
where
    T: APDUDevice,
{
    if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid parameter sizes",
        ));
    }

    let mut register_data = Vec::with_capacity(2 * PARAMETER_SIZE);
    register_data.extend(challenge);
    register_data.extend(application);

    let flags = U2F_REQUEST_USER_PRESENCE;
    let (resp, status) = dev.send_apdu(U2F_REGISTER, flags, &register_data)?;
    apdu_status_to_result(status, resp)
}

pub fn apdu_sign<T>(
    dev: &mut T,
    challenge: &[u8],
    application: &[u8],
    key_handle: &[u8],
) -> io::Result<Vec<u8>>
where
    T: APDUDevice,
{
    if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid parameter sizes",
        ));
    }

    if key_handle.len() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Key handle too large",
        ));
    }

    let mut sign_data = Vec::with_capacity(2 * PARAMETER_SIZE + 1 + key_handle.len());
    sign_data.extend(challenge);
    sign_data.extend(application);
    sign_data.push(key_handle.len() as u8);
    sign_data.extend(key_handle);

    let flags = U2F_REQUEST_USER_PRESENCE;
    let (resp, status) = dev.send_apdu(U2F_AUTHENTICATE, flags, &sign_data)?;
    apdu_status_to_result(status, resp)
}

pub fn apdu_is_keyhandle_valid<T>(
    dev: &mut T,
    challenge: &[u8],
    application: &[u8],
    key_handle: &[u8],
) -> io::Result<bool>
where
    T: APDUDevice,
{
    if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid parameter sizes",
        ));
    }

    if key_handle.len() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Key handle too large",
        ));
    }

    let mut sign_data = Vec::with_capacity(2 * PARAMETER_SIZE + 1 + key_handle.len());
    sign_data.extend(challenge);
    sign_data.extend(application);
    sign_data.push(key_handle.len() as u8);
    sign_data.extend(key_handle);

    let flags = U2F_CHECK_IS_REGISTERED;
    let (_, status) = dev.send_apdu(U2F_AUTHENTICATE, flags, &sign_data)?;
    Ok(status == SW_CONDITIONS_NOT_SATISFIED)
}

pub fn apdu_is_v2_device<T>(dev: &mut T) -> io::Result<bool>
where
    T: APDUDevice,
{
    let (data, status) = dev.send_apdu(U2F_VERSION, 0x00, &[])?;
    let actual = CString::new(data)?;
    let expected = CString::new("U2F_V2")?;
    apdu_status_to_result(status, actual == expected)
}

////////////////////////////////////////////////////////////////////////
// Error Handling
////////////////////////////////////////////////////////////////////////

pub fn apdu_status_to_result<T>(status: [u8; 2], val: T) -> io::Result<T> {
    use self::io::ErrorKind::{InvalidData, InvalidInput};

    match status {
        SW_NO_ERROR => Ok(val),
        SW_WRONG_DATA => Err(io::Error::new(InvalidData, "wrong data")),
        SW_WRONG_LENGTH => Err(io::Error::new(InvalidInput, "wrong length")),
        SW_CONDITIONS_NOT_SATISFIED => Err(io_err("conditions not satisfied")),
        _ => Err(io_err(&format!("failed with status {:?}", status))),
    }
}

// https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
// https://fidoalliance.org/specs/fido-u2f-v1.
// 0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html#u2f-message-framing
pub struct APDU {}

impl APDU {
    pub fn serialize_long(ins: u8, p1: u8, data: &[u8]) -> io::Result<Vec<u8>> {
        let class: u8 = 0x00;
        if data.len() > 0xffff {
            return Err(io_err("payload length > 2^16"));
        }

        // Size of header + data + 2 zero bytes for maximum return size.
        let mut bytes = vec![0u8; U2FAPDUHEADER_SIZE + data.len() + 2];
        bytes[0] = class;
        bytes[1] = ins;
        bytes[2] = p1;
        // p2 is always 0, at least, for our requirements.
        // lc[0] should always be 0.
        bytes[5] = (data.len() >> 8) as u8;
        bytes[6] = data.len() as u8;
        bytes[7..7 + data.len()].copy_from_slice(data);

        // When sending zero data, the two data length bytes should be omitted.
        // Luckily, all later bytes are zero, so we can just truncate.
        if data.is_empty() {
            bytes.truncate(bytes.len() - 2);
        }

        Ok(bytes)
    }

    // This will be used by future NFC code
    #[allow(dead_code)]
    pub fn serialize_short(ins: u8, p1: u8, data: &[u8]) -> io::Result<Vec<u8>> {
        let class: u8 = 0x00;
        if data.len() > 0xff {
            return Err(io_err("payload length > 2^8"));
        }

        let mut size = 5; // class, ins, p1, p2, response size field
        if !data.is_empty() {
            size += 1 + data.len(); // data size field and data itself
        }
        let mut bytes = vec![0u8; size];
        bytes[0] = class;
        bytes[1] = ins;
        bytes[2] = p1;
        // p2 is always 0, at least, for our requirements.
        bytes[4] = data.len() as u8;

        bytes[5..5 + data.len()].copy_from_slice(data);

        Ok(bytes)
    }

    pub fn deserialize(mut data: Vec<u8>) -> io::Result<(Vec<u8>, [u8; 2])> {
        if data.len() < 2 {
            return Err(io_err("unexpected response"));
        }

        let split_at = data.len() - 2;
        let status = data.split_off(split_at);

        Ok((data, [status[0], status[1]]))
    }
}
