use crate::{
    crypto::{PinUvAuthParam, PinUvAuthToken},
    ctap2::server::UserVerificationRequirement,
    errors::AuthenticatorError,
    transport::errors::HIDError,
    FidoDevice,
};
use serde::{
    de::{Error as SerdeError, IgnoredAny, MapAccess, Visitor},
    ser::{Error as SerError, SerializeMap},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_bytes::ByteBuf;
use serde_cbor::{from_slice, to_vec, Value};
use sha2::{Digest, Sha256};
use std::fmt;

use super::{Command, CommandError, CtapResponse, PinUvAuthCommand, RequestCtap2, StatusCode};

#[derive(Debug)]
pub(crate) struct LargeBlobs {
    get: Option<u64>, // (0x01) 	Unsigned integer 	Optional 	The number of bytes requested to read. MUST NOT be present if set is present.
    set: Option<ByteBuf>, // (0x02) 	Byte String 	Optional 	A fragment to write. MUST NOT be present if get is present.
    offset: u64, // (0x03) 	Unsigned integer 	Required 	The byte offset at which to read/write.
    length: Option<u64>, // (0x04) 	Unsigned integer 	Optional 	The total length of a write operation. Present if, and only if, set is present and offset is zero.
    pin_uv_auth_param: Option<PinUvAuthParam>, // (0x05) authenticate(pinUvAuthToken, 32×0xff || h’0c00' || uint32LittleEndian(offset) || SHA-256(contents of set byte string, i.e. not including an outer CBOR tag with major type two))
}

impl PinUvAuthCommand for LargeBlobs {
    fn set_pin_uv_auth_param(
        &mut self,
        pin_uv_auth_token: Option<PinUvAuthToken>,
    ) -> Result<(), AuthenticatorError> {
        let mut param = None;
        if let Some(token) = pin_uv_auth_token {
            // pinUvAuthParam (0x05): the result of calling
            // authenticate(pinUvAuthToken, 32×0xff || h’0c00' || uint32LittleEndian(offset) || SHA-256(contents of set byte string, i.e. not including an outer CBOR tag with major type two))
            let mut data = vec![0xff; 32];
            data.extend([0x0c, 0x00]);
            data.extend((self.offset as u32).to_le_bytes());
            if let Some(ref set) = self.set {
                let mut hasher = Sha256::new();
                hasher.update(set.as_slice());
                data.extend(hasher.finalize().as_slice());
            }
            param = Some(token.derive(&data).map_err(CommandError::Crypto)?);
        }
        self.pin_uv_auth_param = param;
        Ok(())
    }

    fn can_skip_user_verification(
        &mut self,
        _info: &crate::AuthenticatorInfo,
        _uv: UserVerificationRequirement,
    ) -> bool {
        // "discouraged" does not exist for LargeBlobs
        false
    }

    fn set_uv_option(&mut self, _uv: Option<bool>) {
        /* No-op */
    }

    fn get_pin_uv_auth_param(&self) -> Option<&PinUvAuthParam> {
        self.pin_uv_auth_param.as_ref()
    }

    fn get_rp_id(&self) -> Option<&String> {
        None
    }
}

impl Serialize for LargeBlobs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.set.is_none() && self.get.is_none() {
            return Err(SerError::custom("Either set or get has to be set"));
        }
        let mut map_len = 2; // get/set and offset
        if self.length.is_some() {
            map_len += 1;
        }
        if self.pin_uv_auth_param.is_some() {
            map_len += 2;
        }

        let mut map = serializer.serialize_map(Some(map_len))?;
        if let Some(ref get) = self.get {
            map.serialize_entry(&0x01, get)?;
        }
        if let Some(ref set) = self.set {
            map.serialize_entry(&0x02, set)?;
        }
        map.serialize_entry(&0x03, &self.offset)?;
        if let Some(ref length) = self.length {
            map.serialize_entry(&0x04, length)?;
        }
        if let Some(ref pin_uv_auth_param) = self.pin_uv_auth_param {
            map.serialize_entry(&0x05, pin_uv_auth_param)?;
            map.serialize_entry(&0x06, &pin_uv_auth_param.pin_protocol.id())?;
        }
        map.end()
    }
}

impl RequestCtap2 for LargeBlobs {
    type Output = LargeBlobSegment;

    fn command(&self) -> Command {
        Command::LargeBlobs
    }

    fn wire_format(&self) -> Result<Vec<u8>, HIDError> {
        let output = to_vec(&self).map_err(CommandError::Serializing)?;
        trace!("client subcommmand: {:04X?}", &output);
        Ok(output)
    }

    fn handle_response_ctap2<Dev>(
        &self,
        _dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, HIDError>
    where
        Dev: FidoDevice,
    {
        if input.is_empty() {
            return Err(CommandError::InputTooSmall.into());
        }

        let status: StatusCode = input[0].into();
        let payload = &input[1..];
        if status.is_ok() {
            if payload.len() > 1 {
                Ok(payload.to_vec())
            } else {
                // Some subcommands return only an OK-status without any data
                Ok(Vec::new())
            }
        } else {
            let data: Option<Value> = if input.len() > 1 {
                Some(from_slice(payload).map_err(CommandError::Deserializing)?)
            } else {
                None
            };
            Err(CommandError::StatusCode(status, data).into())
        }
    }

    fn send_to_virtual_device<Dev: crate::VirtualFidoDevice>(
        &self,
        _dev: &mut Dev,
    ) -> Result<Self::Output, HIDError> {
        unimplemented!()
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct LargeBlobArrayElement {
    /// AEAD_AES_256_GCM ciphertext, implicitly including the AEAD “authentication tag” at the end.
    pub ciphertext: Vec<u8>,
    /// AEAD_AES_256_GCM nonce. MUST be exactly 12 bytes long.
    pub nonce: [u8; 12],
    /// Contains the length, in bytes, of the uncompressed data.
    pub orig_size: u64,
}

impl Serialize for LargeBlobArrayElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let map_len = 3; // The Array is the only one
        let mut map = serializer.serialize_map(Some(map_len))?;
        map.serialize_entry(&0x01, &self.ciphertext)?;
        map.serialize_entry(&0x02, &self.nonce)?;
        map.serialize_entry(&0x03, &self.orig_size)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for LargeBlobArrayElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LargeBlobArrayElementVisitor;

        impl<'de> Visitor<'de> for LargeBlobArrayElementVisitor {
            type Value = LargeBlobArrayElement;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut ciphertext = None; // Sub-level (0x01)
                let mut nonce = None; // Sub-level (0x02)
                let mut orig_size = None; // Sub-level (0x03)

                // Parsing out the top-level "large-blob array"
                while let Some(key) = map.next_key()? {
                    match key {
                        0x01 => {
                            if ciphertext.is_some() {
                                return Err(SerdeError::duplicate_field("ciphertext"));
                            }
                            ciphertext = Some(map.next_value()?);
                        }
                        0x02 => {
                            if nonce.is_some() {
                                return Err(SerdeError::duplicate_field("nonce"));
                            }
                            nonce = Some(map.next_value()?);
                        }
                        0x03 => {
                            if orig_size.is_some() {
                                return Err(SerdeError::duplicate_field("orig_size"));
                            }
                            orig_size = Some(map.next_value()?);
                        }
                        k => {
                            warn!("LargeBlobArray: unexpected key: {:?}", k);
                            let _ = map.next_value::<IgnoredAny>()?;
                            continue;
                        }
                    }
                }

                let ciphertext = ciphertext.ok_or_else(|| M::Error::missing_field("ciphertext"))?;
                let nonce = nonce.ok_or_else(|| M::Error::missing_field("nonce"))?;
                let orig_size = orig_size.ok_or_else(|| M::Error::missing_field("orig_size"))?;

                Ok(LargeBlobArrayElement {
                    ciphertext,
                    nonce,
                    orig_size,
                })
            }
        }
        deserializer.deserialize_bytes(LargeBlobArrayElementVisitor)
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct LargeBlobsResponse {
    pub(crate) large_blob_array: Vec<LargeBlobArrayElement>,
    /// Truncated SHA-256 hash of the preceding bytes
    pub(crate) hash: [u8; 16],
    pub(crate) byte_len: u64,
}

impl<'de> Deserialize<'de> for LargeBlobsResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LargeBlobsResponseVisitor;

        impl<'de> Visitor<'de> for LargeBlobsResponseVisitor {
            type Value = LargeBlobsResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                // this data is serialized as a CBOR-encoded array (called the large-blob array) of large-blob maps, concatenated with 16 following bytes. Those final 16 bytes are the truncated SHA-256 hash of the preceding bytes.
                let mut response = None; // Top-level 0x01

                // Parsing out the top-level "large-blob array"
                while let Some(key) = map.next_key()? {
                    match key {
                        0x01 => {
                            if response.is_some() {
                                return Err(SerdeError::duplicate_field("response"));
                            }
                            let payload: ByteBuf = map.next_value()?;
                            // Note: the minimum length of a serialized large-blob array is 17 bytes. Omitting 16 bytes for the trailing SHA-256 hash, this leaves just one byte. This is the size of an empty CBOR array.
                            if payload.len() < 17 {
                                return Err(SerdeError::invalid_length(
                                    payload.len(),
                                    &">= 17 bytes",
                                ));
                            }
                            // split off trailing hash-bytes
                            let (mut large_blob, mut hash_slice) =
                                payload.split_at(payload.len() - 16);

                            let mut hasher = Sha256::new();
                            hasher.update(large_blob);
                            let expected_hash = hasher.finalize();
                            // The initial serialized large-blob array is the value of the serialized large-blob array on a fresh authenticator, as well as immediately after a reset. It is the byte string h'8076be8b528d0075f7aae98d6fa57a6d3c', which is an empty CBOR array (80) followed by LEFT(SHA-256(h'80'), 16).
                            let default_large_blob = [0x80];
                            let default_hash = [
                                0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d,
                                0x6f, 0xa5, 0x7a, 0x6d, 0x3c,
                            ];
                            // Once complete, the platform MUST confirm that the embedded SHA-256 hash is correct, based on the definition above. If not, the configuration is corrupt and the platform MUST discard it and act as if the initial serialized large-blob array was received.
                            if &expected_hash.as_slice()[0..16] != hash_slice {
                                warn!("Large blob array hash doesn't match with the expected value! Assuming an empty array.");
                                large_blob = &default_large_blob;
                                hash_slice = &default_hash;
                            }

                            let byte_len = large_blob.len() as u64;
                            let large_blob_array: Vec<LargeBlobArrayElement> =
                                from_slice(large_blob).unwrap();
                            let mut hash = [0u8; 16];
                            hash.copy_from_slice(hash_slice);
                            response = Some(LargeBlobsResponse {
                                large_blob_array,
                                hash,
                                byte_len,
                            });
                        }
                        k => {
                            warn!("LargeBlobsResponse: unexpected key: {:?}", k);
                            let _ = map.next_value::<IgnoredAny>()?;
                            continue;
                        }
                    }
                }
                let response =
                    response.ok_or_else(|| M::Error::missing_field("large_blob_bytes"))?;

                Ok(response)
            }
        }
        deserializer.deserialize_bytes(LargeBlobsResponseVisitor)
    }
}

pub type LargeBlobSegment = Vec<u8>;

impl CtapResponse for LargeBlobSegment {}

pub fn read_large_blob_array<Dev>(
    dev: &mut Dev,
    keep_alive: &dyn Fn() -> bool,
) -> Result<LargeBlobsResponse, AuthenticatorError>
where
    Dev: FidoDevice,
{
    // Spec:
    // A per-authenticator constant, maxFragmentLength, is here defined as the value of maxMsgSize (from the authenticatorGetInfo response) minus 64.
    // If no maxMsgSize is given in the authenticatorGetInfo response) then it defaults to 1024, leaving maxFragmentLength to default to 960.
    let max_fragment_length = dev
        .get_authenticator_info()
        .and_then(|i| i.max_msg_size)
        .unwrap_or(1024)
        - 64;
    let mut bytes = vec![];
    let mut offset = 0;
    loop {
        let cmd = LargeBlobs {
            get: Some(max_fragment_length as u64),
            set: None,
            offset,
            length: None,
            pin_uv_auth_param: None,
        };
        let mut segment = dev.send_cbor_cancellable(&cmd, keep_alive)?;
        let segment_len = segment.len();
        bytes.append(&mut segment);
        // Spec:
        // If the length of the response is equal to the value of get then more data may be
        // available and the platform SHOULD repeatedly issue requests, each time updating offset
        // to equal the amount of data received so far. It stops once a short (or empty)
        // fragment is returned.
        if segment_len < max_fragment_length {
            // The last segment was smaller than the max-size
            // so we have read all there is to read.
            break;
        } else {
            // There is still more data. So set the offset and repeat
            offset += segment_len as u64;
            continue;
        }
    }
    let response: LargeBlobsResponse = from_slice(&bytes).map_err(CommandError::Deserializing)?;
    Ok(response)
}

pub fn write_large_blob_segment<Dev>(
    dev: &mut Dev,
    keep_alive: &dyn Fn() -> bool,
    bytes: &[u8],
    initial_offset: u64,
    pin_uv_auth_token: Option<PinUvAuthToken>,
) -> Result<(), AuthenticatorError>
where
    Dev: FidoDevice,
{
    // Spec:
    // A per-authenticator constant, maxFragmentLength, is here defined as the value of maxMsgSize (from the authenticatorGetInfo response) minus 64.
    // If no maxMsgSize is given in the authenticatorGetInfo response) then it defaults to 1024, leaving maxFragmentLength to default to 960.
    let max_fragment_length = dev
        .get_authenticator_info()
        .and_then(|i| i.max_msg_size)
        .unwrap_or(1024)
        - 64;
    let total_length = bytes.len();
    let mut offset = initial_offset;
    for chunk in bytes.chunks(max_fragment_length) {
        let chunk_len = chunk.len();
        let mut cmd = LargeBlobs {
            get: None,
            set: Some(ByteBuf::from(chunk)),
            offset,
            length: if offset == 0 {
                Some(total_length as u64)
            } else {
                None
            },
            pin_uv_auth_param: None,
        };
        cmd.set_pin_uv_auth_param(pin_uv_auth_token.clone())?;
        dev.send_cbor_cancellable(&cmd, keep_alive)?;
        offset += chunk_len as u64;
    }
    Ok(())
}

pub fn add_large_blob<Dev>(
    dev: &mut Dev,
    keep_alive: &dyn Fn() -> bool,
    blob: LargeBlobArrayElement,
    pin_uv_auth_token: Option<PinUvAuthToken>,
) -> Result<(), AuthenticatorError>
where
    Dev: FidoDevice,
{
    let mut array = read_large_blob_array(dev, keep_alive)?;
    // Adding it
    array.large_blob_array.push(blob);
    // Then rewriting the whole array
    let mut bytes = to_vec(&array.large_blob_array).map_err(CommandError::Serializing)?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    bytes.extend_from_slice(&hash[..16]);
    write_large_blob_segment(dev, keep_alive, &bytes, 0, pin_uv_auth_token)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::consts::HIDCmd;
    use crate::transport::device_selector::Device;
    use crate::transport::hid::HIDDevice;
    use crate::transport::platform::device::{IN_HID_RPT_SIZE, OUT_HID_RPT_SIZE};
    use crate::transport::{FidoDevice, FidoProtocol};
    use rand::{thread_rng, RngCore};

    fn add_bytes_to_read(cid: &[u8], bytes: &[u8], device: &mut Device) {
        let mut data = Vec::new();
        let payload_len = (bytes.len() + 1) as u16;
        // We skip the very first byte (HIDCmd::Cbor), as we will insert it below
        data.extend(payload_len.to_be_bytes());
        data.push(0x00); // status == success
        data.extend(bytes);
        let chunks = data.chunks(IN_HID_RPT_SIZE - 5);
        for (id, chunk) in chunks.enumerate() {
            let mut msg = cid.to_vec();
            let state_or_seq = if id == 0 {
                HIDCmd::Cbor.into()
            } else {
                (id - 1) as u8 // SEQ
            };
            msg.push(state_or_seq);
            msg.extend(chunk);
            device.add_read(&msg, 0);
        }
    }

    fn add_bytes_to_write(cid: &[u8], bytes: &[u8], device: &mut Device) {
        let mut data = Vec::new();
        let payload_len = (bytes.len()) as u16;
        // We skip the very first byte (HIDCmd::Cbor), as we will insert it below
        data.extend(payload_len.to_be_bytes());
        data.extend(bytes);
        let chunks = data.chunks(OUT_HID_RPT_SIZE - 5);
        for (id, chunk) in chunks.enumerate() {
            let mut msg = cid.to_vec();
            let state_or_seq = if id == 0 {
                HIDCmd::Cbor.into()
            } else {
                (id - 1) as u8 // SEQ
            };
            msg.push(state_or_seq);
            msg.extend(chunk);
            device.add_write(&msg, 0);
        }
    }

    #[test]
    fn test_read_large_blob_array() {
        let keep_alive = || true;
        let mut device = Device::new("commands/large_blobs").unwrap();
        assert_eq!(device.get_protocol(), FidoProtocol::CTAP2);

        // 'initialize' the device
        let mut cid = [0u8; 4];
        thread_rng().fill_bytes(&mut cid);
        device.set_cid(cid);

        let cmd = [
            0xa2, // map(2)
            0x01, // unsigned(1) - get
            0x19, 0x03, 0xc0, // unsigned(960)
            0x03, // unsigned(3) - offset
            0x00, // unsigned(0)
        ];
        let mut msg = cid.to_vec();
        msg.extend(vec![HIDCmd::Cbor.into(), 0x00, cmd.len() as u8 + 1]); // cmd + bcnt
        msg.extend(vec![0x0C]); // LargeBlobs
        msg.extend(cmd); // Actual command
        device.add_write(&msg, 0);

        add_bytes_to_read(&cid, &LARGE_BLOB_ARRAY, &mut device);
        let array = read_large_blob_array(&mut device, &keep_alive)
            .expect("Failed to read large blob array");
        let expected = get_expected_large_blobs_response();
        assert_eq!(expected, array);
    }

    #[test]
    fn test_read_large_blob_array_with_wrong_hash() {
        let keep_alive = || true;
        let mut device = Device::new("commands/large_blobs").unwrap();
        assert_eq!(device.get_protocol(), FidoProtocol::CTAP2);

        // 'initialize' the device
        let mut cid = [0u8; 4];
        thread_rng().fill_bytes(&mut cid);
        device.set_cid(cid);

        let cmd = [
            0xa2, // map(2)
            0x01, // unsigned(1) - get
            0x19, 0x03, 0xc0, // unsigned(960)
            0x03, // unsigned(3) - offset
            0x00, // unsigned(0)
        ];
        let mut msg = cid.to_vec();
        msg.extend(vec![HIDCmd::Cbor.into(), 0x00, cmd.len() as u8 + 1]); // cmd + bcnt
        msg.extend(vec![0x0C]); // LargeBlobs
        msg.extend(cmd); // Actual command
        device.add_write(&msg, 0);

        let mut payload = LARGE_BLOB_ARRAY;
        payload[483] += 1; // Changing one byte in the hash

        add_bytes_to_read(&cid, &payload, &mut device);
        // Should succeed, but give us the default empty Large blob array, as defined by the spec
        let array = read_large_blob_array(&mut device, &keep_alive)
            .expect("Failed to read large blob array");
        let expected = LargeBlobsResponse {
            large_blob_array: vec![],
            hash: [
                0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a,
                0x6d, 0x3c,
            ],
            byte_len: 1,
        };
        assert_eq!(expected, array);
    }

    #[test]
    fn test_read_large_blob_array_multi_read() {
        let keep_alive = || true;
        let mut device = Device::new("commands/large_blobs").unwrap();
        assert_eq!(device.get_protocol(), FidoProtocol::CTAP2);
        device.set_authenticator_info(crate::AuthenticatorInfo {
            max_msg_size: Some(164), // Note: This value minus 64 will be the fragment size
            ..Default::default()
        });

        // 'initialize' the device
        let mut cid = [0u8; 4];
        thread_rng().fill_bytes(&mut cid);
        device.set_cid(cid);

        for ii in 0..5 {
            let mut cmd = vec![
                0xa2, // map(2)
                0x01, // unsigned(1) - get
                0x18, 0x64, // unsigned(100)
                0x03, // unsigned(3) - offset
            ];
            cmd.extend(&to_vec(&serde_cbor::Value::Integer(ii * 100)).unwrap());
            let mut msg = cid.to_vec();
            msg.extend(vec![HIDCmd::Cbor.into(), 0x00, cmd.len() as u8 + 1]); // cmd + bcnt
            msg.extend(vec![0x0C]); // LargeBlobs
            msg.extend(cmd); // Actual command
            device.add_write(&msg, 0);
        }

        for chunk in LARGE_BLOB_ARRAY.chunks(100) {
            add_bytes_to_read(&cid, chunk, &mut device);
        }
        let array = read_large_blob_array(&mut device, &keep_alive)
            .expect("Failed to read large blob array");
        let expected = get_expected_large_blobs_response();
        assert_eq!(expected, array);
    }

    #[test]
    fn test_add_large_blob_element() {
        let keep_alive = || true;
        let mut device = Device::new("commands/large_blobs").unwrap();
        assert_eq!(device.get_protocol(), FidoProtocol::CTAP2);

        // First we read the whole existing array
        let mut cid = [0u8; 4];
        thread_rng().fill_bytes(&mut cid);
        device.set_cid(cid);

        let cmd = [
            0xa2, // map(2)
            0x01, // unsigned(1) - get
            0x19, 0x03, 0xc0, // unsigned(960)
            0x03, // unsigned(3) - offset
            0x00, // unsigned(0)
        ];
        let mut msg = cid.to_vec();
        msg.extend(vec![HIDCmd::Cbor.into(), 0x00, cmd.len() as u8 + 1]); // cmd + bcnt
        msg.extend(vec![0x0C]); // LargeBlobs
        msg.extend(cmd); // Actual command
        device.add_write(&msg, 0);

        add_bytes_to_read(&cid, &LARGE_BLOB_ARRAY, &mut device);

        // Now add write-command
        let mut cmd = vec![
            0x0C, // LargeBlobs
            0xa3, // map(3)
            0x02, // unsigned(1) - set
            0x59, 0x02, 0x78, // unsigned(632) 479+153
        ];
        cmd.extend(LARGE_BLOB_ARRAY_LONGER);
        cmd.extend([
            0x03, // unsigned(3) - offset
            0x00, // unsigned(0)
            0x04, // unsigned(4) - length
            0x19, 0x02, 0x78, // unsigned(631)
        ]);
        add_bytes_to_write(&cid, &cmd, &mut device);

        // empty success-command
        add_bytes_to_read(&cid, &[], &mut device);

        let add_parsed = additional_blob_element();
        add_large_blob(&mut device, &keep_alive, add_parsed, None)
            .expect("Failed to write add large blob element");
    }

    #[test]
    fn test_add_large_blob_element_multi_write() {
        let keep_alive = || true;
        let mut device = Device::new("commands/large_blobs").unwrap();
        assert_eq!(device.get_protocol(), FidoProtocol::CTAP2);
        device.set_authenticator_info(crate::AuthenticatorInfo {
            max_msg_size: Some(164), // Note: This value minus 64 will be the fragment size
            ..Default::default()
        });

        // First we read the whole existing array
        let mut cid = [0u8; 4];
        thread_rng().fill_bytes(&mut cid);
        device.set_cid(cid);

        for ii in 0..5 {
            let mut cmd = vec![
                0xa2, // map(2)
                0x01, // unsigned(1) - get
                0x18, 0x64, // unsigned(100)
                0x03, // unsigned(3) - offset
            ];
            cmd.extend(&to_vec(&serde_cbor::Value::Integer(ii * 100)).unwrap());
            let mut msg = cid.to_vec();
            msg.extend(vec![HIDCmd::Cbor.into(), 0x00, cmd.len() as u8 + 1]); // cmd + bcnt
            msg.extend(vec![0x0C]); // LargeBlobs
            msg.extend(cmd); // Actual command
            device.add_write(&msg, 0);
        }

        for chunk in LARGE_BLOB_ARRAY.chunks(100) {
            add_bytes_to_read(&cid, chunk, &mut device);
        }

        // Now add write-command
        for (ii, chunk) in LARGE_BLOB_ARRAY_LONGER.chunks(100).enumerate() {
            let mut cmd = vec![
                0x0C, // LargeBlobs
            ];

            if ii == 0 {
                cmd.push(0xa3); // map(3) // with 'length'
            } else {
                cmd.push(0xa2); // map(2) // without 'length'
            }
            cmd.push(0x02); // unsigned(1) - set
            if ii == 6 {
                cmd.extend([0x58, 0x20]); // unsigned(32) Remaining bytes
            } else {
                cmd.extend([0x58, 0x64]); // unsigned(100) Remaining bytes
            }

            cmd.extend(chunk);
            cmd.push(0x03); // unsigned(3) - offset
            cmd.extend(&to_vec(&serde_cbor::Value::Integer((ii * 100) as i128)).unwrap());
            if ii == 0 {
                cmd.extend([
                    0x04, // unsigned(4) - length
                    0x19, 0x02, 0x78, // unsigned(631)
                ]);
            }
            add_bytes_to_write(&cid, &cmd, &mut device);

            // empty success-command
            add_bytes_to_read(&cid, &[], &mut device);
        }

        let add_parsed = additional_blob_element();
        add_large_blob(&mut device, &keep_alive, add_parsed, None)
            .expect("Failed to write add large blob element");
    }

    fn additional_blob_element() -> LargeBlobArrayElement {
        LargeBlobArrayElement {
            ciphertext: vec![
                116, 199, 82, 206, 68, 131, 237, 242, 213, 144, 244, 185, 155, 148, 217, 62, 245,
                5, 128, 162, 176, 99, 5, 160, 186, 68, 88, 140, 38, 255, 168, 254, 88, 161, 188,
                30, 113, 221, 67, 21, 88, 43, 211, 17, 190, 252, 14, 186, 225, 200, 135, 186, 168,
                255, 232, 51, 151, 183, 194, 134, 160, 250, 191, 141,
            ],
            nonce: [117, 86, 137, 126, 205, 2, 34, 50, 18, 20, 165, 104],
            orig_size: 34,
        }
    }
    fn get_expected_large_blobs_response() -> LargeBlobsResponse {
        LargeBlobsResponse {
            large_blob_array: vec![
                LargeBlobArrayElement {
                    ciphertext: vec![
                        116, 199, 82, 206, 68, 131, 237, 242, 213, 144, 244, 185, 155, 148, 217,
                        62, 245, 5, 128, 162, 176, 99, 5, 160, 186, 68, 88, 140, 38, 255, 168, 254,
                        88, 161, 188, 30, 113, 221, 67, 21, 88, 43, 211, 17, 190, 252, 14, 186,
                        225, 200, 135, 186, 168, 255, 232, 51, 151, 183, 194, 134, 160, 250, 191,
                        141,
                    ],
                    nonce: [117, 86, 137, 126, 205, 2, 34, 50, 18, 20, 165, 104],
                    orig_size: 34,
                },
                LargeBlobArrayElement {
                    ciphertext: vec![
                        71, 124, 111, 114, 77, 240, 163, 5, 124, 7, 191, 2, 177, 167, 200, 95, 248,
                        163, 235, 77, 195, 106, 253, 23, 183, 119, 55, 17, 50, 238, 217, 248, 56,
                        135, 48, 49, 101, 132, 66, 78, 58, 23, 101, 77, 52, 213, 89, 73, 34, 61,
                        237, 8, 219, 1, 208, 245, 129, 101, 234, 114, 170, 54, 7, 147, 59, 226, 32,
                    ],
                    nonce: [99, 132, 251, 236, 134, 156, 86, 195, 121, 49, 205, 162],
                    orig_size: 36,
                },
                LargeBlobArrayElement {
                    ciphertext: vec![
                        212, 135, 116, 12, 170, 245, 186, 103, 147, 112, 196, 29, 43, 120, 236,
                        175, 205, 84, 184, 231, 118, 152, 76, 60, 216, 128, 204, 166, 96, 8, 67, 3,
                        163, 242, 243, 124, 156, 65, 138, 98, 66, 46, 201, 40, 219, 236, 53, 43,
                        107, 14, 135, 23, 99, 150, 240, 14, 234, 153, 115, 94, 180, 117, 162, 213,
                    ],
                    nonce: [231, 165, 15, 21, 64, 8, 234, 133, 6, 223, 226, 134],
                    orig_size: 34,
                },
            ],
            hash: [
                0x15, 0xee, 0x84, 0xa0, 0xce, 0x5d, 0xa7, 0xd6, 0x6d, 0x3e, 0xb6, 0xf2, 0xc1, 0x40,
                0x28, 0x65,
            ],
            byte_len: 463,
        }
    }

    #[rustfmt::skip]
    pub const LARGE_BLOB_ARRAY: [u8; 484] = [
        0xa1, // map(1)
          0x01, // unsigned(1)
          0x59, 0x01, 0xdf, // bytes(479)
            0x83,             // array(3)
              0xa3,          //   map(3)
                0x01,       //     unsigned(1) - ciphertext
                0x98, 0x40, //     array(64)
                  0x18, 0x74, 0x18, 0xc7, 0x18, 0x52, 0x18, 0xce, 0x18, 0x44, 0x18, 0x83, 0x18, 0xed, 0x18, 0xf2, 0x18, 0xd5, 0x18, 0x90, 0x18, 0xf4, 0x18, 0xb9, 0x18, 0x9b, 0x18, 0x94, 0x18, 0xd9, 0x18, 0x3e, 0x18, 0xf5, 0x05, 0x18, 0x80, 0x18, 0xa2, 0x18, 0xb0, 0x18, 0x63, 0x05, 0x18, 0xa0, 0x18, 0xba, 0x18, 0x44, 0x18, 0x58, 0x18, 0x8c, 0x18, 0x26, 0x18, 0xff, 0x18, 0xa8, 0x18, 0xfe, 0x18, 0x58, 0x18, 0xa1, 0x18, 0xbc, 0x18, 0x1e, 0x18, 0x71, 0x18, 0xdd, 0x18, 0x43, 0x15, 0x18, 0x58, 0x18, 0x2b, 0x18, 0xd3, 0x11, 0x18, 0xbe, 0x18, 0xfc, 0x0e, 0x18, 0xba, 0x18, 0xe1, 0x18, 0xc8, 0x18, 0x87, 0x18, 0xba, 0x18, 0xa8, 0x18, 0xff, 0x18, 0xe8, 0x18, 0x33, 0x18, 0x97, 0x18, 0xb7, 0x18, 0xc2, 0x18, 0x86, 0x18, 0xa0, 0x18, 0xfa, 0x18, 0xbf, 0x18, 0x8d, 
                0x02,       //     unsigned(2) - nonce
                0x8c,       //     array(12)
                  0x18, 0x75, 0x18, 0x56, 0x18, 0x89, 0x18, 0x7e, 0x18, 0xcd, 0x02, 0x18, 0x22, 0x18, 0x32, 0x12, 0x14, 0x18, 0xa5, 0x18, 0x68,
                0x03,       //     unsigned(3) - origSize
                0x18, 0x22, //     unsigned(34)
              0xa3,          //   map(3)
                0x01,       //     unsigned(1) - ciphertext
                0x98, 0x43,    //     array(67)
                  0x18, 0x47, 0x18, 0x7c, 0x18, 0x6f, 0x18, 0x72, 0x18, 0x4d, 0x18, 0xf0, 0x18, 0xa3, 0x05, 0x18, 0x7c, 0x07, 0x18, 0xbf, 0x02, 0x18, 0xb1, 0x18, 0xa7, 0x18, 0xc8, 0x18, 0x5f, 0x18, 0xf8, 0x18, 0xa3, 0x18, 0xeb, 0x18, 0x4d, 0x18, 0xc3, 0x18, 0x6a, 0x18, 0xfd, 0x17, 0x18, 0xb7, 0x18, 0x77, 0x18, 0x37, 0x11, 0x18, 0x32, 0x18, 0xee, 0x18, 0xd9, 0x18, 0xf8, 0x18, 0x38, 0x18, 0x87, 0x18, 0x30, 0x18, 0x31, 0x18, 0x65, 0x18, 0x84, 0x18, 0x42, 0x18, 0x4e, 0x18, 0x3a, 0x17, 0x18, 0x65, 0x18, 0x4d, 0x18, 0x34, 0x18, 0xd5, 0x18, 0x59, 0x18, 0x49, 0x18, 0x22, 0x18, 0x3d, 0x18, 0xed, 0x08, 0x18, 0xdb, 0x01, 0x18, 0xd0, 0x18, 0xf5, 0x18, 0x81, 0x18, 0x65, 0x18, 0xea, 0x18, 0x72, 0x18, 0xaa, 0x18, 0x36, 0x07, 0x18, 0x93, 0x18, 0x3b, 0x18, 0xe2, 0x18, 0x20,
                0x02,       //     unsigned(2)
                0x8c,       //     array(12) - nonce
                  0x18, 0x63, 0x18, 0x84, 0x18, 0xfb, 0x18, 0xec, 0x18, 0x86, 0x18, 0x9c, 0x18, 0x56, 0x18, 0xc3, 0x18, 0x79, 0x18, 0x31, 0x18, 0xcd, 0x18, 0xa2,
                0x03,       //     unsigned(3) - origSize
                0x18, 0x24,    //     unsigned(36)
              0xa3,          //   map(3)
                0x01,       //     unsigned(1) - ciphertext
                0x98, 0x40,    //     array(64)
                  0x18, 0xd4, 0x18, 0x87, 0x18, 0x74, 0x0c, 0x18, 0xaa, 0x18, 0xf5, 0x18, 0xba, 0x18, 0x67, 0x18, 0x93, 0x18, 0x70, 0x18, 0xc4, 0x18, 0x1d, 0x18, 0x2b, 0x18, 0x78, 0x18, 0xec, 0x18, 0xaf, 0x18, 0xcd, 0x18, 0x54, 0x18, 0xb8, 0x18, 0xe7, 0x18, 0x76, 0x18, 0x98, 0x18, 0x4c, 0x18, 0x3c, 0x18, 0xd8, 0x18, 0x80, 0x18, 0xcc, 0x18, 0xa6, 0x18, 0x60, 0x08, 0x18, 0x43, 0x03, 0x18, 0xa3, 0x18, 0xf2, 0x18, 0xf3, 0x18, 0x7c, 0x18, 0x9c, 0x18, 0x41, 0x18, 0x8a, 0x18, 0x62, 0x18, 0x42, 0x18, 0x2e, 0x18, 0xc9, 0x18, 0x28, 0x18, 0xdb, 0x18, 0xec, 0x18, 0x35, 0x18, 0x2b, 0x18, 0x6b, 0x0e, 0x18, 0x87, 0x17, 0x18, 0x63, 0x18, 0x96, 0x18, 0xf0, 0x0e, 0x18, 0xea, 0x18, 0x99, 0x18, 0x73, 0x18, 0x5e, 0x18, 0xb4, 0x18, 0x75, 0x18, 0xa2, 0x18, 0xd5,
                0x02,       //     unsigned(2) - nonce
                0x8c,       //     array(12)
                  0x18, 0xe7, 0x18, 0xa5, 0x0f, 0x15, 0x18, 0x40, 0x08, 0x18, 0xea, 0x18, 0x85, 0x06, 0x18, 0xdf, 0x18, 0xe2, 0x18, 0x86,
                0x03,       //     unsigned(3) - origSize
                0x18, 0x22,    //     unsigned(34)
           0x15, 0xee, 0x84, 0xa0, 0xce, 0x5d, 0xa7, 0xd6, 0x6d, 0x3e, 0xb6, 0xf2, 0xc1, 0x40, 0x28, 0x65 // trailing hash-bytes
    ];

    #[rustfmt::skip]
    pub const LARGE_BLOB_ARRAY_LONGER: [u8; 632] = [
        // Skipping initial map(1) -> unsigned(1) ->  bytes(632), as we have to change that with
        // fragmented writes
            0x84,             // array(4)
              0xa3,          //   map(3)
                0x01,       //     unsigned(1) - ciphertext
                0x98, 0x40, //     array(64)
                  0x18, 0x74, 0x18, 0xc7, 0x18, 0x52, 0x18, 0xce, 0x18, 0x44, 0x18, 0x83, 0x18, 0xed, 0x18, 0xf2, 0x18, 0xd5, 0x18, 0x90, 0x18, 0xf4, 0x18, 0xb9, 0x18, 0x9b, 0x18, 0x94, 0x18, 0xd9, 0x18, 0x3e, 0x18, 0xf5, 0x05, 0x18, 0x80, 0x18, 0xa2, 0x18, 0xb0, 0x18, 0x63, 0x05, 0x18, 0xa0, 0x18, 0xba, 0x18, 0x44, 0x18, 0x58, 0x18, 0x8c, 0x18, 0x26, 0x18, 0xff, 0x18, 0xa8, 0x18, 0xfe, 0x18, 0x58, 0x18, 0xa1, 0x18, 0xbc, 0x18, 0x1e, 0x18, 0x71, 0x18, 0xdd, 0x18, 0x43, 0x15, 0x18, 0x58, 0x18, 0x2b, 0x18, 0xd3, 0x11, 0x18, 0xbe, 0x18, 0xfc, 0x0e, 0x18, 0xba, 0x18, 0xe1, 0x18, 0xc8, 0x18, 0x87, 0x18, 0xba, 0x18, 0xa8, 0x18, 0xff, 0x18, 0xe8, 0x18, 0x33, 0x18, 0x97, 0x18, 0xb7, 0x18, 0xc2, 0x18, 0x86, 0x18, 0xa0, 0x18, 0xfa, 0x18, 0xbf, 0x18, 0x8d, 
                0x02,       //     unsigned(2) - nonce
                0x8c,       //     array(12)
                  0x18, 0x75, 0x18, 0x56, 0x18, 0x89, 0x18, 0x7e, 0x18, 0xcd, 0x02, 0x18, 0x22, 0x18, 0x32, 0x12, 0x14, 0x18, 0xa5, 0x18, 0x68,
                0x03,       //     unsigned(3) - origSize
                0x18, 0x22, //     unsigned(34)
              0xa3,          //   map(3)
                0x01,       //     unsigned(1) - ciphertext
                0x98, 0x43,    //     array(67)
                  0x18, 0x47, 0x18, 0x7c, 0x18, 0x6f, 0x18, 0x72, 0x18, 0x4d, 0x18, 0xf0, 0x18, 0xa3, 0x05, 0x18, 0x7c, 0x07, 0x18, 0xbf, 0x02, 0x18, 0xb1, 0x18, 0xa7, 0x18, 0xc8, 0x18, 0x5f, 0x18, 0xf8, 0x18, 0xa3, 0x18, 0xeb, 0x18, 0x4d, 0x18, 0xc3, 0x18, 0x6a, 0x18, 0xfd, 0x17, 0x18, 0xb7, 0x18, 0x77, 0x18, 0x37, 0x11, 0x18, 0x32, 0x18, 0xee, 0x18, 0xd9, 0x18, 0xf8, 0x18, 0x38, 0x18, 0x87, 0x18, 0x30, 0x18, 0x31, 0x18, 0x65, 0x18, 0x84, 0x18, 0x42, 0x18, 0x4e, 0x18, 0x3a, 0x17, 0x18, 0x65, 0x18, 0x4d, 0x18, 0x34, 0x18, 0xd5, 0x18, 0x59, 0x18, 0x49, 0x18, 0x22, 0x18, 0x3d, 0x18, 0xed, 0x08, 0x18, 0xdb, 0x01, 0x18, 0xd0, 0x18, 0xf5, 0x18, 0x81, 0x18, 0x65, 0x18, 0xea, 0x18, 0x72, 0x18, 0xaa, 0x18, 0x36, 0x07, 0x18, 0x93, 0x18, 0x3b, 0x18, 0xe2, 0x18, 0x20,
                0x02,       //     unsigned(2)
                0x8c,       //     array(12) - nonce
                  0x18, 0x63, 0x18, 0x84, 0x18, 0xfb, 0x18, 0xec, 0x18, 0x86, 0x18, 0x9c, 0x18, 0x56, 0x18, 0xc3, 0x18, 0x79, 0x18, 0x31, 0x18, 0xcd, 0x18, 0xa2,
                0x03,       //     unsigned(3) - origSize
                0x18, 0x24,    //     unsigned(36)
              0xa3,          //   map(3)
                0x01,       //     unsigned(1) - ciphertext
                0x98, 0x40,    //     array(64)
                  0x18, 0xd4, 0x18, 0x87, 0x18, 0x74, 0x0c, 0x18, 0xaa, 0x18, 0xf5, 0x18, 0xba, 0x18, 0x67, 0x18, 0x93, 0x18, 0x70, 0x18, 0xc4, 0x18, 0x1d, 0x18, 0x2b, 0x18, 0x78, 0x18, 0xec, 0x18, 0xaf, 0x18, 0xcd, 0x18, 0x54, 0x18, 0xb8, 0x18, 0xe7, 0x18, 0x76, 0x18, 0x98, 0x18, 0x4c, 0x18, 0x3c, 0x18, 0xd8, 0x18, 0x80, 0x18, 0xcc, 0x18, 0xa6, 0x18, 0x60, 0x08, 0x18, 0x43, 0x03, 0x18, 0xa3, 0x18, 0xf2, 0x18, 0xf3, 0x18, 0x7c, 0x18, 0x9c, 0x18, 0x41, 0x18, 0x8a, 0x18, 0x62, 0x18, 0x42, 0x18, 0x2e, 0x18, 0xc9, 0x18, 0x28, 0x18, 0xdb, 0x18, 0xec, 0x18, 0x35, 0x18, 0x2b, 0x18, 0x6b, 0x0e, 0x18, 0x87, 0x17, 0x18, 0x63, 0x18, 0x96, 0x18, 0xf0, 0x0e, 0x18, 0xea, 0x18, 0x99, 0x18, 0x73, 0x18, 0x5e, 0x18, 0xb4, 0x18, 0x75, 0x18, 0xa2, 0x18, 0xd5,
                0x02,       //     unsigned(2) - nonce
                0x8c,       //     array(12)
                  0x18, 0xe7, 0x18, 0xa5, 0x0f, 0x15, 0x18, 0x40, 0x08, 0x18, 0xea, 0x18, 0x85, 0x06, 0x18, 0xdf, 0x18, 0xe2, 0x18, 0x86,
                0x03,       //     unsigned(3) - origSize
                0x18, 0x22,    //     unsigned(34)
              0xa3,          //   map(3)
                0x01,       //     unsigned(1) - ciphertext
                0x98, 0x40, //     array(64)
                  0x18, 0x74, 0x18, 0xc7, 0x18, 0x52, 0x18, 0xce, 0x18, 0x44, 0x18, 0x83, 0x18, 0xed, 0x18, 0xf2, 0x18, 0xd5, 0x18, 0x90, 0x18, 0xf4, 0x18, 0xb9, 0x18, 0x9b, 0x18, 0x94, 0x18, 0xd9, 0x18, 0x3e, 0x18, 0xf5, 0x05, 0x18, 0x80, 0x18, 0xa2, 0x18, 0xb0, 0x18, 0x63, 0x05, 0x18, 0xa0, 0x18, 0xba, 0x18, 0x44, 0x18, 0x58, 0x18, 0x8c, 0x18, 0x26, 0x18, 0xff, 0x18, 0xa8, 0x18, 0xfe, 0x18, 0x58, 0x18, 0xa1, 0x18, 0xbc, 0x18, 0x1e, 0x18, 0x71, 0x18, 0xdd, 0x18, 0x43, 0x15, 0x18, 0x58, 0x18, 0x2b, 0x18, 0xd3, 0x11, 0x18, 0xbe, 0x18, 0xfc, 0x0e, 0x18, 0xba, 0x18, 0xe1, 0x18, 0xc8, 0x18, 0x87, 0x18, 0xba, 0x18, 0xa8, 0x18, 0xff, 0x18, 0xe8, 0x18, 0x33, 0x18, 0x97, 0x18, 0xb7, 0x18, 0xc2, 0x18, 0x86, 0x18, 0xa0, 0x18, 0xfa, 0x18, 0xbf, 0x18, 0x8d, 
                0x02,       //     unsigned(2) - nonce
                0x8c,       //     array(12)
                  0x18, 0x75, 0x18, 0x56, 0x18, 0x89, 0x18, 0x7e, 0x18, 0xcd, 0x02, 0x18, 0x22, 0x18, 0x32, 0x12, 0x14, 0x18, 0xa5, 0x18, 0x68,
                0x03,       //     unsigned(3) - origSize
                0x18, 0x22, //     unsigned(34)
            0xb9, 0xd5, 0x4e, 0x96, 0xcf, 0x6e, 0xd8, 0xf6, 0xb4, 0x4c, 0x2e, 0xdc, 0xec, 0x76, 0x67, 0x0, // trailing hash-bytes
    ];
}
