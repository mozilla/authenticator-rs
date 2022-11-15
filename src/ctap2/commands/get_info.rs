use super::{Command, CommandError, RequestCtap2, StatusCode};
use crate::ctap2::attestation::AAGuid;
use crate::ctap2::server::PublicKeyCredentialParameters;
use crate::transport::errors::HIDError;
use crate::u2ftypes::U2FDevice;
use serde::{
    de::{Error as SError, IgnoredAny, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_cbor::{de::from_slice, Value};
use std::fmt;

#[derive(Debug)]
pub struct GetInfo {}

impl Default for GetInfo {
    fn default() -> GetInfo {
        GetInfo {}
    }
}

impl RequestCtap2 for GetInfo {
    type Output = AuthenticatorInfo;

    fn command() -> Command {
        Command::GetInfo
    }

    fn wire_format<Dev>(&self, _dev: &mut Dev) -> Result<Vec<u8>, HIDError>
    where
        Dev: U2FDevice,
    {
        Ok(Vec::new())
    }

    fn handle_response_ctap2<Dev>(
        &self,
        _dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, HIDError>
    where
        Dev: U2FDevice,
    {
        if input.is_empty() {
            return Err(CommandError::InputTooSmall.into());
        }

        let status: StatusCode = input[0].into();

        if input.len() > 1 {
            if status.is_ok() {
                trace!("parsing authenticator info data: {:#04X?}", &input);
                let authenticator_info =
                    from_slice(&input[1..]).map_err(CommandError::Deserializing)?;
                Ok(authenticator_info)
            } else {
                let data: Value = from_slice(&input[1..]).map_err(CommandError::Deserializing)?;
                Err(CommandError::StatusCode(status, Some(data)).into())
            }
        } else {
            Err(CommandError::InputTooSmall.into())
        }
    }
}

fn true_val() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
pub(crate) struct AuthenticatorOptions {
    /// Indicates that the device is attached to the client and therefore can’t
    /// be removed and used on another client.
    #[serde(rename = "plat", default)]
    pub(crate) platform_device: bool,
    /// Indicates that the device is capable of storing keys on the device
    /// itself and therefore can satisfy the authenticatorGetAssertion request
    /// with allowList parameter not specified or empty.
    #[serde(rename = "rk", default)]
    pub(crate) resident_key: bool,

    /// Client PIN:
    ///  If present and set to true, it indicates that the device is capable of
    ///   accepting a PIN from the client and PIN has been set.
    ///  If present and set to false, it indicates that the device is capable of
    ///   accepting a PIN from the client and PIN has not been set yet.
    ///  If absent, it indicates that the device is not capable of accepting a
    ///   PIN from the client.
    /// Client PIN is one of the ways to do user verification.
    #[serde(rename = "clientPin")]
    pub(crate) client_pin: Option<bool>,

    /// Indicates that the device is capable of testing user presence.
    #[serde(rename = "up", default = "true_val")]
    pub(crate) user_presence: bool,

    /// Indicates that the device is capable of verifying the user within
    /// itself. For example, devices with UI, biometrics fall into this
    /// category.
    ///  If present and set to true, it indicates that the device is capable of
    ///   user verification within itself and has been configured.
    ///  If present and set to false, it indicates that the device is capable of
    ///   user verification within itself and has not been yet configured. For
    ///   example, a biometric device that has not yet been configured will
    ///   return this parameter set to false.
    ///  If absent, it indicates that the device is not capable of user
    ///   verification within itself.
    /// A device that can only do Client PIN will not return the "uv" parameter.
    /// If a device is capable of verifying the user within itself as well as
    /// able to do Client PIN, it will return both "uv" and the Client PIN
    /// option.
    // TODO(MS): My Token (key-ID FIDO2) does return Some(false) here, even though
    //           it has no built-in verification method. Not to be trusted...
    #[serde(rename = "uv")]
    pub(crate) user_verification: Option<bool>,
}

impl Default for AuthenticatorOptions {
    fn default() -> Self {
        AuthenticatorOptions {
            platform_device: false,
            resident_key: false,
            client_pin: None,
            user_presence: true,
            user_verification: None,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthenticatorInfo {
    pub(crate) versions: Vec<String>,
    pub(crate) extensions: Vec<String>,
    pub(crate) aaguid: AAGuid,
    pub(crate) options: AuthenticatorOptions,
    pub(crate) max_msg_size: Option<usize>,
    pub(crate) pin_protocols: Vec<u32>,
    // CTAP 2.1
    pub(crate) max_credential_count_in_list: Option<usize>,
    pub(crate) max_credential_id_length: Option<usize>,
    pub(crate) transports: Option<Vec<String>>,
    pub(crate) algorithms: Option<Vec<PublicKeyCredentialParameters>>,
    // lots more to come
}

impl AuthenticatorInfo {
    pub fn supports_hmac_secret(&self) -> bool {
        self.extensions.contains(&"hmac-secret".to_string())
    }
}

impl<'de> Deserialize<'de> for AuthenticatorInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AuthenticatorInfoVisitor;

        impl<'de> Visitor<'de> for AuthenticatorInfoVisitor {
            type Value = AuthenticatorInfo;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut versions = Vec::new();
                let mut extensions = Vec::new();
                let mut aaguid = None;
                let mut options = AuthenticatorOptions::default();
                let mut max_msg_size = None;
                let mut pin_protocols = Vec::new();
                let mut max_credential_count_in_list = None;
                let mut max_credential_id_length = None;
                let mut transports = None;
                let mut algorithms = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        1 => {
                            if !versions.is_empty() {
                                return Err(serde::de::Error::duplicate_field("versions"));
                            }
                            versions = map.next_value()?;
                        }
                        2 => {
                            if !extensions.is_empty() {
                                return Err(serde::de::Error::duplicate_field("extensions"));
                            }
                            extensions = map.next_value()?;
                        }
                        3 => {
                            if aaguid.is_some() {
                                return Err(serde::de::Error::duplicate_field("aaguid"));
                            }
                            aaguid = Some(map.next_value()?);
                        }
                        4 => {
                            options = map.next_value()?;
                        }
                        5 => {
                            max_msg_size = Some(map.next_value()?);
                        }
                        6 => {
                            pin_protocols = map.next_value()?;
                        }
                        7 => {
                            if max_credential_count_in_list.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "max_credential_count_in_list",
                                ));
                            }
                            max_credential_count_in_list = Some(map.next_value()?);
                        }
                        8 => {
                            if max_credential_id_length.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "max_credential_id_length",
                                ));
                            }
                            max_credential_id_length = Some(map.next_value()?);
                        }
                        9 => {
                            if transports.is_some() {
                                return Err(serde::de::Error::duplicate_field("transports"));
                            }
                            transports = Some(map.next_value()?);
                        }
                        10 => {
                            if algorithms.is_some() {
                                return Err(serde::de::Error::duplicate_field("algorithms"));
                            }
                            algorithms = Some(map.next_value()?);
                        }
                        k => {
                            warn!("GetInfo: unexpected key: {:?}", k);
                            let _ = map.next_value::<IgnoredAny>()?;
                            continue;
                        }
                    }
                }

                if versions.is_empty() {
                    return Err(M::Error::custom(
                        "expected at least one version, got none".to_string(),
                    ));
                }

                if let Some(aaguid) = aaguid {
                    Ok(AuthenticatorInfo {
                        versions,
                        extensions,
                        aaguid,
                        options,
                        max_msg_size,
                        pin_protocols,
                        max_credential_count_in_list,
                        max_credential_id_length,
                        transports,
                        algorithms,
                    })
                } else {
                    Err(M::Error::custom("No AAGuid specified".to_string()))
                }
            }
        }

        deserializer.deserialize_bytes(AuthenticatorInfoVisitor)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::consts::{Capability, HIDCmd, CID_BROADCAST};
    use crate::crypto::COSEAlgorithm;
    use crate::transport::device_selector::Device;
    use crate::transport::platform::device::IN_HID_RPT_SIZE;
    use crate::transport::{hid::HIDDevice, FidoDevice, Nonce};
    use crate::u2ftypes::U2FDevice;
    use rand::{thread_rng, RngCore};
    use serde_cbor::de::from_slice;

    // Raw data take from https://github.com/Yubico/python-fido2/blob/master/test/test_ctap2.py
    pub const AAGUID_RAW: [u8; 16] = [
        0xF8, 0xA0, 0x11, 0xF3, 0x8C, 0x0A, 0x4D, 0x15, 0x80, 0x06, 0x17, 0x11, 0x1F, 0x9E, 0xDC,
        0x7D,
    ];

    pub const AUTHENTICATOR_INFO_PAYLOAD: [u8; 89] = [
        0xa6, 0x01, 0x82, 0x66, 0x55, 0x32, 0x46, 0x5f, 0x56, 0x32, 0x68, 0x46, 0x49, 0x44, 0x4f,
        0x5f, 0x32, 0x5f, 0x30, 0x02, 0x82, 0x63, 0x75, 0x76, 0x6d, 0x6b, 0x68, 0x6d, 0x61, 0x63,
        0x2d, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x03, 0x50, 0xf8, 0xa0, 0x11, 0xf3, 0x8c, 0x0a,
        0x4d, 0x15, 0x80, 0x06, 0x17, 0x11, 0x1f, 0x9e, 0xdc, 0x7d, 0x04, 0xa4, 0x62, 0x72, 0x6b,
        0xf5, 0x62, 0x75, 0x70, 0xf5, 0x64, 0x70, 0x6c, 0x61, 0x74, 0xf4, 0x69, 0x63, 0x6c, 0x69,
        0x65, 0x6e, 0x74, 0x50, 0x69, 0x6e, 0xf4, 0x05, 0x19, 0x04, 0xb0, 0x06, 0x81, 0x01,
    ];

    // Real world example from Yubikey Bio
    pub const AUTHENTICATOR_INFO_PAYLOAD_YK_BIO_5C: [u8; 409] = [
        0xB3, 0x01, 0x84, 0x66, 0x55, 0x32, 0x46, 0x5F, 0x56, 0x32, 0x68, 0x46, 0x49, 0x44, 0x4F,
        0x5F, 0x32, 0x5F, 0x30, 0x6C, 0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x31, 0x5F, 0x50,
        0x52, 0x45, 0x68, 0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x31, 0x02, 0x85, 0x6B, 0x63,
        0x72, 0x65, 0x64, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x6B, 0x68, 0x6D, 0x61, 0x63,
        0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x6C, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x42, 0x6C,
        0x6F, 0x62, 0x4B, 0x65, 0x79, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0x6C,
        0x6D, 0x69, 0x6E, 0x50, 0x69, 0x6E, 0x4C, 0x65, 0x6E, 0x67, 0x74, 0x68, 0x03, 0x50, 0xD8,
        0x52, 0x2D, 0x9F, 0x57, 0x5B, 0x48, 0x66, 0x88, 0xA9, 0xBA, 0x99, 0xFA, 0x02, 0xF3, 0x5B,
        0x04, 0xB0, 0x62, 0x72, 0x6B, 0xF5, 0x62, 0x75, 0x70, 0xF5, 0x62, 0x75, 0x76, 0xF5, 0x64,
        0x70, 0x6C, 0x61, 0x74, 0xF4, 0x67, 0x75, 0x76, 0x54, 0x6F, 0x6B, 0x65, 0x6E, 0xF5, 0x68,
        0x61, 0x6C, 0x77, 0x61, 0x79, 0x73, 0x55, 0x76, 0xF5, 0x68, 0x63, 0x72, 0x65, 0x64, 0x4D,
        0x67, 0x6D, 0x74, 0xF5, 0x69, 0x61, 0x75, 0x74, 0x68, 0x6E, 0x72, 0x43, 0x66, 0x67, 0xF5,
        0x69, 0x62, 0x69, 0x6F, 0x45, 0x6E, 0x72, 0x6F, 0x6C, 0x6C, 0xF5, 0x69, 0x63, 0x6C, 0x69,
        0x65, 0x6E, 0x74, 0x50, 0x69, 0x6E, 0xF5, 0x6A, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x42, 0x6C,
        0x6F, 0x62, 0x73, 0xF5, 0x6E, 0x70, 0x69, 0x6E, 0x55, 0x76, 0x41, 0x75, 0x74, 0x68, 0x54,
        0x6F, 0x6B, 0x65, 0x6E, 0xF5, 0x6F, 0x73, 0x65, 0x74, 0x4D, 0x69, 0x6E, 0x50, 0x49, 0x4E,
        0x4C, 0x65, 0x6E, 0x67, 0x74, 0x68, 0xF5, 0x70, 0x6D, 0x61, 0x6B, 0x65, 0x43, 0x72, 0x65,
        0x64, 0x55, 0x76, 0x4E, 0x6F, 0x74, 0x52, 0x71, 0x64, 0xF4, 0x75, 0x63, 0x72, 0x65, 0x64,
        0x65, 0x6E, 0x74, 0x69, 0x61, 0x6C, 0x4D, 0x67, 0x6D, 0x74, 0x50, 0x72, 0x65, 0x76, 0x69,
        0x65, 0x77, 0xF5, 0x78, 0x1B, 0x75, 0x73, 0x65, 0x72, 0x56, 0x65, 0x72, 0x69, 0x66, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x4D, 0x67, 0x6D, 0x74, 0x50, 0x72, 0x65, 0x76, 0x69,
        0x65, 0x77, 0xF5, 0x05, 0x19, 0x04, 0xB0, 0x06, 0x82, 0x02, 0x01, 0x07, 0x08, 0x08, 0x18,
        0x80, 0x09, 0x81, 0x63, 0x75, 0x73, 0x62, 0x0A, 0x82, 0xA2, 0x63, 0x61, 0x6C, 0x67, 0x26,
        0x64, 0x74, 0x79, 0x70, 0x65, 0x6A, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65,
        0x79, 0xA2, 0x63, 0x61, 0x6C, 0x67, 0x27, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6A, 0x70, 0x75,
        0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79, 0x0B, 0x19, 0x04, 0x00, 0x0C, 0xF4, 0x0D,
        0x04, 0x0E, 0x1A, 0x00, 0x05, 0x05, 0x06, 0x0F, 0x18, 0x20, 0x10, 0x01, 0x11, 0x03, 0x12,
        0x02, 0x14, 0x18, 0x18,
    ];

    #[test]
    fn parse_authenticator_info() {
        let authenticator_info: AuthenticatorInfo =
            from_slice(&AUTHENTICATOR_INFO_PAYLOAD).unwrap();

        let expected = AuthenticatorInfo {
            versions: vec!["U2F_V2".to_string(), "FIDO_2_0".to_string()],
            extensions: vec!["uvm".to_string(), "hmac-secret".to_string()],
            aaguid: AAGuid(AAGUID_RAW),
            options: AuthenticatorOptions {
                platform_device: false,
                resident_key: true,
                client_pin: Some(false),
                user_presence: true,
                user_verification: None,
            },
            max_msg_size: Some(1200),
            pin_protocols: vec![1],
            max_credential_count_in_list: None,
            max_credential_id_length: None,
            transports: None,
            algorithms: None,
        };

        assert_eq!(authenticator_info, expected);
    }

    #[test]
    fn parse_unsupported_authenticator_info() {
        let authenticator_info: AuthenticatorInfo =
            from_slice(&AUTHENTICATOR_INFO_PAYLOAD_YK_BIO_5C).unwrap();

        let expected = AuthenticatorInfo {
            versions: vec![
                "U2F_V2".to_string(),
                "FIDO_2_0".to_string(),
                "FIDO_2_1_PRE".to_string(),
                "FIDO_2_1".to_string(),
            ],
            extensions: vec![
                "credProtect".to_string(),
                "hmac-secret".to_string(),
                "largeBlobKey".to_string(),
                "credBlob".to_string(),
                "minPinLength".to_string(),
            ],
            aaguid: AAGuid([
                0xd8, 0x52, 0x2d, 0x9f, 0x57, 0x5b, 0x48, 0x66, 0x88, 0xa9, 0xba, 0x99, 0xfa, 0x02,
                0xf3, 0x5b,
            ]),
            options: AuthenticatorOptions {
                platform_device: false,
                resident_key: true,
                client_pin: Some(true),
                user_presence: true,
                user_verification: Some(true),
            },
            max_msg_size: Some(1200),
            pin_protocols: vec![2, 1],
            max_credential_count_in_list: Some(8),
            max_credential_id_length: Some(128),
            transports: Some(vec!["usb".to_string()]),
            algorithms: Some(vec![
                PublicKeyCredentialParameters {
                    alg: COSEAlgorithm::ES256,
                },
                PublicKeyCredentialParameters {
                    alg: COSEAlgorithm::EDDSA,
                },
            ]),
        };

        assert_eq!(authenticator_info, expected);
    }

    #[test]
    fn test_get_info_ctap2_only() {
        let mut device = Device::new("commands/get_info").unwrap();
        let nonce = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];

        // channel id
        let mut cid = [0u8; 4];
        thread_rng().fill_bytes(&mut cid);

        // init packet
        let mut msg = CID_BROADCAST.to_vec();
        msg.extend(vec![HIDCmd::Init.into(), 0x00, 0x08]); // cmd + bcnt
        msg.extend_from_slice(&nonce);
        device.add_write(&msg, 0);

        // init_resp packet
        let mut msg = CID_BROADCAST.to_vec();
        msg.extend(vec![
            0x06, /*HIDCmd::Init without TYPE_INIT*/
            0x00, 0x11,
        ]); // cmd + bcnt
        msg.extend_from_slice(&nonce);
        msg.extend_from_slice(&cid); // new channel id

        // We are setting NMSG, to signal that the device does not support CTAP1
        msg.extend(vec![0x02, 0x04, 0x01, 0x08, 0x01 | 0x04 | 0x08]); // versions + flags (wink+cbor+nmsg)
        device.add_read(&msg, 0);

        // ctap2 request
        let mut msg = cid.to_vec();
        msg.extend(vec![HIDCmd::Cbor.into(), 0x00, 0x1]); // cmd + bcnt
        msg.extend(vec![0x04]); // authenticatorGetInfo
        device.add_write(&msg, 0);

        // ctap2 response
        let mut msg = cid.to_vec();
        msg.extend(vec![HIDCmd::Cbor.into(), 0x00, 0x5A]); // cmd + bcnt
        msg.extend(vec![0]); // Status code: Success
        msg.extend(&AUTHENTICATOR_INFO_PAYLOAD[0..(IN_HID_RPT_SIZE - 8)]);
        device.add_read(&msg, 0);
        // Continuation package
        let mut msg = cid.to_vec();
        msg.extend(vec![0x00]); // SEQ
        msg.extend(&AUTHENTICATOR_INFO_PAYLOAD[(IN_HID_RPT_SIZE - 8)..]);
        device.add_read(&msg, 0);
        device
            .init(Nonce::Use(nonce))
            .expect("Failed to init device");

        assert_eq!(device.get_cid(), &cid);

        let dev_info = device.get_device_info();
        assert_eq!(
            dev_info.cap_flags,
            Capability::WINK | Capability::CBOR | Capability::NMSG
        );

        let result = device
            .get_authenticator_info()
            .expect("Didn't get any authenticator_info");
        let expected = AuthenticatorInfo {
            versions: vec!["U2F_V2".to_string(), "FIDO_2_0".to_string()],
            extensions: vec!["uvm".to_string(), "hmac-secret".to_string()],
            aaguid: AAGuid(AAGUID_RAW),
            options: AuthenticatorOptions {
                platform_device: false,
                resident_key: true,
                client_pin: Some(false),
                user_presence: true,
                user_verification: None,
            },
            max_msg_size: Some(1200),
            pin_protocols: vec![1],
            max_credential_count_in_list: None,
            max_credential_id_length: None,
            transports: None,
            algorithms: None,
        };

        assert_eq!(result, &expected);
    }
}
