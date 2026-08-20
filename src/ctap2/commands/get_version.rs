use super::{CommandError, CtapResponse, RequestCtap1, Retryable};
use crate::consts::U2F_VERSION;
use crate::transport::errors::{ApduErrorStatus, HIDError};
use crate::transport::{FidoDevice, VirtualFidoDevice};
use crate::u2ftypes::CTAP1RequestAPDU;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum U2FInfo {
    U2F_V2,
}

impl CtapResponse for U2FInfo {}

#[derive(Debug, Default)]
// TODO(baloo): if one does not issue U2F_VERSION before makecredentials or getassertion, token
//              will return error (ConditionsNotSatified), test this in unit tests
pub struct GetVersion {}

impl RequestCtap1 for GetVersion {
    type Output = U2FInfo;
    type AdditionalInfo = ();

    fn handle_response_ctap1<Dev: FidoDevice>(
        &self,
        _dev: &mut Dev,
        _status: Result<(), ApduErrorStatus>,
        input: &[u8],
        _add_info: &(),
    ) -> Result<Self::Output, Retryable<HIDError>> {
        if input.is_empty() {
            return Err(Retryable::Error(HIDError::Command(
                CommandError::InputTooSmall,
            )));
        }

        let expected = String::from("U2F_V2");
        let result = String::from_utf8_lossy(input);
        match result {
            ref data if data == &expected => Ok(U2FInfo::U2F_V2),
            _ => Err(Retryable::Error(HIDError::UnexpectedVersion)),
        }
    }

    fn ctap1_format(&self) -> Result<(Vec<u8>, ()), HIDError> {
        let flags = 0;

        let cmd = U2F_VERSION;
        let data = CTAP1RequestAPDU::serialize(cmd, flags, &[])?;
        Ok((data, ()))
    }

    fn send_to_virtual_device<Dev: VirtualFidoDevice>(
        &self,
        dev: &mut Dev,
    ) -> Result<Self::Output, HIDError> {
        dev.get_version(self)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::consts::Capability;
    use crate::transport::device_selector::Device;
    use crate::transport::{hid::HIDDevice, FidoDevice, FidoProtocol};
    use crate::CtapVersionSupport;

    #[test]
    fn test_get_version_ctap1_only() {
        let mut device = Device::new_pre_inited("commands/get_version", Capability::WINK);

        device.downgrade_to_ctap1().expect("failed to downgrade");
        assert_eq!(device.get_protocol(), FidoProtocol::CTAP1);
        assert!(device.supports_ctap1());
        assert!(!device.supports_ctap2());

        let dev_info = device.get_device_info();
        assert_eq!(dev_info.cap_flags, Capability::WINK);

        let result = device.get_authenticator_info();
        assert!(result.is_none());
    }
}
