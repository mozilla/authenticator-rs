use super::{Command, CommandError, RequestCtap2, StatusCode};
use crate::ctap2::commands::get_assertion::GetAssertionResponse;
use crate::transport::errors::HIDError;
use crate::u2ftypes::U2FDevice;
use serde_cbor::{de::from_slice, Value};

#[derive(Debug)]
pub(crate) struct GetNextAssertion;

impl RequestCtap2 for GetNextAssertion {
    type Output = GetAssertionResponse;

    fn command() -> Command {
        Command::GetNextAssertion
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
        debug!("response status code: {:?}", status);
        if input.len() > 1 {
            if status.is_ok() {
                let assertion = from_slice(&input[1..]).map_err(CommandError::Parsing)?;
                // TODO(baloo): check assertion response does not have numberOfCredentials
                Ok(assertion)
            } else {
                let data: Value = from_slice(&input[1..]).map_err(CommandError::Parsing)?;
                Err(CommandError::StatusCode(status, Some(data))).map_err(HIDError::Command)
            }
        } else if status.is_ok() {
            Err(CommandError::InputTooSmall).map_err(HIDError::Command)
        } else {
            Err(CommandError::StatusCode(status, None)).map_err(HIDError::Command)
        }
    }
}
