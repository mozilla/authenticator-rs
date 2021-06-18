use super::{Command, CommandError, RequestCtap2, StatusCode};
use crate::transport::errors::HIDError;
use crate::u2ftypes::U2FDevice;
use serde::{
    de::{Error as SError, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_cbor::{de::from_slice, Value};
use std::fmt;

#[derive(Serialize, PartialEq, Eq, Clone)]
pub struct AAGuid(pub [u8; 16]);

impl AAGuid {
    fn from(src: &[u8]) -> Result<AAGuid, ()> {
        let mut payload = [0u8; 16];
        if src.len() != payload.len() {
            Err(())
        } else {
            payload.copy_from_slice(src);
            Ok(AAGuid(payload))
        }
    }

    pub fn empty() -> Self {
        AAGuid([0u8; 16])
    }
}

impl fmt::Debug for AAGuid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "AAGuid({:x}{:x}{:x}{:x}-{:x}{:x}-{:x}{:x}-{:x}{:x}-{:x}{:x}{:x}{:x}{:x}{:x})",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5],
            self.0[6],
            self.0[7],
            self.0[8],
            self.0[9],
            self.0[10],
            self.0[11],
            self.0[12],
            self.0[13],
            self.0[14],
            self.0[15]
        )
    }
}

impl<'de> Deserialize<'de> for AAGuid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AAGuidVisitor;

        impl<'de> Visitor<'de> for AAGuidVisitor {
            type Value = AAGuid;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: SError,
            {
                if v.len() != 16 {
                    return Err(E::custom("expecting 16 bytes data"));
                }

                let mut buf = [0u8; 16];

                buf.copy_from_slice(v);

                Ok(AAGuid(buf))
            }
        }

        deserializer.deserialize_bytes(AAGuidVisitor)
    }
}

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
            return Err(CommandError::InputTooSmall).map_err(HIDError::Command);
        }

        let status: StatusCode = input[0].into();

        if input.len() > 1 {
            if status.is_ok() {
                trace!("parsing authenticator info data: {:#04X?}", &input);
                let authenticator_info =
                    from_slice(&input[1..]).map_err(CommandError::Deserializing)?;
                Ok(authenticator_info)
            } else {
                let data: Value = from_slice(&input[1..]).map_err(CommandError::Parsing)?;
                Err(HIDError::Command(CommandError::StatusCode(
                    status,
                    Some(data),
                )))
            }
        } else {
            Err(CommandError::InputTooSmall).map_err(HIDError::Command)
        }
    }
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
pub(crate) struct AuthenticatorOptions {
    /// Indicates that the device is attached to the client and therefore can’t
    /// be removed and used on another client.
    #[serde(rename = "plat")]
    pub(crate) platform_device: bool,
    /// Indicates that the device is capable of storing keys on the device
    /// itself and therefore can satisfy the authenticatorGetAssertion request
    /// with allowList parameter not specified or empty.
    #[serde(rename = "rk")]
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
    #[serde(rename = "up")]
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthenticatorInfo {
    pub(crate) versions: Vec<String>,
    pub(crate) extensions: Vec<String>,
    pub(crate) aaguid: AAGuid,
    pub(crate) options: AuthenticatorOptions,
    pub(crate) max_msg_size: Option<usize>,
    pub(crate) pin_protocols: Vec<u32>,
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
                        k => return Err(M::Error::custom(format!("unexpected key: {:?}", k))),
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
    use crate::transport::{FidoDevice, Nonce};
    use crate::u2fprotocol::tests::platform::{TestDevice, IN_HID_RPT_SIZE};
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
        };

        assert_eq!(authenticator_info, expected);
    }

    #[test]
    fn test_get_info_ctap2_only() {
        let mut device = TestDevice::new();
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

        let result =
            FidoDevice::get_authenticator_info(&device).expect("Didn't get any authenticator_info");
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
        };

        assert_eq!(result, &expected);
    }
}
