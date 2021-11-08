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
            return Err(CommandError::InputTooSmall.into());
        }

        let status: StatusCode = input[0].into();
        debug!("response status code: {:?}", status);
        if input.len() > 1 {
            if status.is_ok() {
                let assertion = from_slice(&input[1..]).map_err(CommandError::Deserializing)?;
                // TODO(baloo): check assertion response does not have numberOfCredentials
                Ok(assertion)
            } else {
                let data: Value = from_slice(&input[1..]).map_err(CommandError::Deserializing)?;
                Err(CommandError::StatusCode(status, Some(data)).into())
            }
        } else if status.is_ok() {
            Err(CommandError::InputTooSmall.into())
        } else {
            Err(CommandError::StatusCode(status, None).into())
        }
    }
}
