use super::{Command, CommandError, RequestCtap2, StatusCode};
use crate::transport::errors::HIDError;
use crate::u2ftypes::U2FDevice;
use serde_cbor::{de::from_slice, Value};

#[derive(Debug, Default)]
pub struct Reset {}

impl RequestCtap2 for Reset {
    type Output = ();

    fn command() -> Command {
        Command::Reset
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

        if status.is_ok() {
            Ok(())
        } else {
            let msg = if input.len() > 1 {
                let data: Value = from_slice(&input[1..]).map_err(CommandError::Deserializing)?;
                Some(data)
            } else {
                None
            };
            Err(CommandError::StatusCode(status, msg).into())
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::consts::HIDCmd;
    use crate::transport::device_selector::Device;
    use crate::transport::{hid::HIDDevice, FidoDevice};
    use crate::u2ftypes::U2FDevice;
    use rand::{thread_rng, RngCore};
    use serde_cbor::{de::from_slice, Value};

    fn issue_command_and_get_response(cmd: u8, add: &[u8]) -> Result<(), HIDError> {
        let mut device = Device::new("commands/Reset").unwrap();
        // ctap2 request
        let mut cid = [0u8; 4];
        thread_rng().fill_bytes(&mut cid);
        device.set_cid(cid);

        let mut msg = cid.to_vec();
        msg.extend(vec![HIDCmd::Cbor.into(), 0x00, 0x1]); // cmd + bcnt
        msg.extend(vec![0x07]); // authenticatorReset
        device.add_write(&msg, 0);

        // ctap2 response
        let len = 0x1 + add.len() as u8;
        let mut msg = cid.to_vec();
        msg.extend(vec![HIDCmd::Cbor.into(), 0x00, len]); // cmd + bcnt
        msg.push(cmd); // Status code
        msg.extend(add); // + maybe additional data
        device.add_read(&msg, 0);

        device.send_cbor(&Reset {})
    }

    #[test]
    fn test_select_ctap2_only() {
        // Test, if we can parse the status codes specified by the spec

        // Ok()
        issue_command_and_get_response(0, &[]).expect("Unexpected error");

        // Denied by the user
        let response = issue_command_and_get_response(0x27, &[]).expect_err("Not an error!");
        assert!(matches!(
            response,
            HIDError::Command(CommandError::StatusCode(StatusCode::OperationDenied, None))
        ));

        // Timeout
        let response = issue_command_and_get_response(0x2F, &[]).expect_err("Not an error!");
        assert!(matches!(
            response,
            HIDError::Command(CommandError::StatusCode(
                StatusCode::UserActionTimeout,
                None
            ))
        ));

        // Unexpected error with more random CBOR-data
        let add_data = vec![
            0x63, // text(3)
            0x61, 0x6c, 0x67, // "alg"
        ];
        let response = issue_command_and_get_response(0x02, &add_data).expect_err("Not an error!");
        match response {
            HIDError::Command(CommandError::StatusCode(StatusCode::InvalidParameter, Some(d))) => {
                let expected: Value = from_slice(&add_data).unwrap();
                assert_eq!(d, expected)
            }
            e => panic!("Not the expected response: {:?}", e),
        }
    }
}
