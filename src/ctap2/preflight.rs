use crate::consts::{PARAMETER_SIZE, U2F_AUTHENTICATE, U2F_CHECK_IS_REGISTERED};
use crate::ctap2::server::{PublicKeyCredentialDescriptor, RelyingPartyWrapper};
use crate::errors::AuthenticatorError;
use crate::transport::errors::{ApduErrorStatus, HIDError};
use crate::transport::platform::device::Device;
use crate::transport::FidoDevice;
use crate::u2ftypes::{CTAP1RequestAPDU, U2FDevice};
use std::fmt;
use std::io;

use super::commands::get_info::AuthenticatorInfo;
use super::commands::{RequestCtap1, Retryable};

/// This command is used to check which key_handle is valid for this
/// token. This is sent before a GetAssertion command, to determine which
/// is valid for a specific token and which key_handle GetAssertion
/// should send to the token. Or before a MakeCredential command, to determine
/// if this token is already registered or not.
#[derive(Debug)]
pub(crate) struct CheckKeyHandle<'assertion> {
    pub(crate) key_handle: &'assertion [u8],
    pub(crate) client_data_hash: &'assertion [u8],
    pub(crate) rp: &'assertion RelyingPartyWrapper,
}

impl<'assertion> RequestCtap1 for CheckKeyHandle<'assertion> {
    type Output = ();
    type AdditionalInfo = ();

    fn ctap1_format<Dev>(&self, _dev: &mut Dev) -> Result<(Vec<u8>, Self::AdditionalInfo), HIDError>
    where
        Dev: U2FDevice + io::Read + io::Write + fmt::Debug,
    {
        let flags = U2F_CHECK_IS_REGISTERED;
        // TODO(MS): Need to check "up" here. If up==false, set to 0x08? Or not? Spec is
        // ambiguous
        let mut auth_data = Vec::with_capacity(2 * PARAMETER_SIZE + 1 + self.key_handle.len());

        auth_data.extend_from_slice(self.client_data_hash);
        auth_data.extend_from_slice(self.rp.hash().as_ref());
        auth_data.extend_from_slice(&[self.key_handle.len() as u8]);
        auth_data.extend_from_slice(self.key_handle);
        let cmd = U2F_AUTHENTICATE;
        let apdu = CTAP1RequestAPDU::serialize(cmd, flags, &auth_data)?;
        Ok((apdu, ()))
    }

    fn handle_response_ctap1(
        &self,
        status: Result<(), ApduErrorStatus>,
        _input: &[u8],
        _add_info: &Self::AdditionalInfo,
    ) -> Result<Self::Output, Retryable<HIDError>> {
        // From the U2F-spec: https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#registration-request-message---u2f_register
        // if the control byte is set to 0x07 by the FIDO Client, the U2F token is supposed to
        // simply check whether the provided key handle was originally created by this token,
        // and whether it was created for the provided application parameter. If so, the U2F
        // token MUST respond with an authentication response
        // message:error:test-of-user-presence-required (note that despite the name this
        // signals a success condition). If the key handle was not created by this U2F
        // token, or if it was created for a different application parameter, the token MUST
        // respond with an authentication response message:error:bad-key-handle.
        match status {
            Ok(_) | Err(ApduErrorStatus::ConditionsNotSatisfied) => Ok(()),
            Err(e) => Err(Retryable::Error(HIDError::ApduStatus(e))),
        }
    }
}

pub(crate) trait PreFlightable {
    fn get_credential_id_list(&self) -> &[PublicKeyCredentialDescriptor];
    fn set_credential_id_list(&mut self, list: Vec<PublicKeyCredentialDescriptor>);
    /// "pre-flight": In order to determine whether authenticatorMakeCredential's excludeList or
    /// authenticatorGetAssertion's allowList contain credential IDs that are already
    /// present on an authenticator, a platform typically invokes authenticatorGetAssertion
    /// with the "up" option key set to false and optionally pinUvAuthParam one or more times.
    fn do_pre_flight<Dev: FidoDevice>(&mut self, dev: &mut Dev) -> Result<(), AuthenticatorError> {
        // // If there is max. one entry, we can skip all of this
        // if self.get_credential_id_list().len() <= 1 {
        //     return Ok(());
        // }

        debug!("------------------------------------------------------------------");
        debug!("Doing pre-flight");
        debug!("------------------------------------------------------------------");

        // Step 1: Split the excludeList/allowList according to the capabilities of the token
        // Step 1.1: Find out how long the exclude_list/allow_list is allowed to be
        //           If the token doesn't tell us, we assume a length of 1
        // TODO(MS): Chromium also checks the max_credential_id_length, and if that is 0 also
        //           falls back to max_list_len = 1, but doesn't give an explanation as to why.
        match dev.get_authenticator_info() {
            Some(info) => {
                self.do_pre_flight_ctap2(info.max_credential_count_in_list.unwrap_or(1), dev)
            }
            None => self.do_pre_flight_ctap1(dev),
        }
    }
    fn do_pre_flight_ctap1<Dev: FidoDevice>(
        &mut self,
        dev: &mut Dev,
    ) -> Result<(), AuthenticatorError>;
    fn do_pre_flight_ctap2<Dev: FidoDevice>(
        &mut self,
        chunk_size: usize,
        dev: &mut Dev,
    ) -> Result<(), AuthenticatorError>;
}
