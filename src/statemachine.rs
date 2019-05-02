/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//use consts::PARAMETER_SIZE;
//use std::thread;
//use std::time::Duration;
use transport::platform::device::Device;
use transport::platform::transaction::Transaction;
use transport::{Error, FidoDevice};
//use u2fprotocol::{u2f_init_device, u2f_is_keyhandle_valid, u2f_register, u2f_sign};
use util::{Callback, OnceCallback, OnceCallbackMap};

use crate::ctap::CollectedClientData;
use crate::ctap2::attestation::AttestationObject;
use crate::ctap2::commands::{AssertionObject, GetAssertion, MakeCredentials};

//fn is_valid_transport(transports: ::AuthenticatorTransports) -> bool {
//    transports.is_empty() || transports.contains(::AuthenticatorTransports::USB)
//}

//fn find_valid_key_handles<'a, F>(
//    app_ids: &'a [::AppId],
//    key_handles: &'a [::KeyHandle],
//    mut is_valid: F,
//) -> (&'a ::AppId, Vec<&'a ::KeyHandle>)
//where
//    F: FnMut(&Vec<u8>, &::KeyHandle) -> bool,
//{
//    // Try all given app_ids in order.
//    for app_id in app_ids {
//        // Find all valid key handles for the current app_id.
//        let valid_handles = key_handles
//            .iter()
//            .filter(|key_handle| is_valid(app_id, key_handle))
//            .collect::<Vec<_>>();
//
//        // If there's at least one, stop.
//        if !valid_handles.is_empty() {
//            return (app_id, valid_handles);
//        }
//    }
//
//    (&app_ids[0], vec![])
//}

#[derive(Default)]
pub struct StateMachine {
    transaction: Option<Transaction>,
}

impl StateMachine {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn register<CB>(&mut self, timeout: u64, params: MakeCredentials, callback: CB)
    where
        CB: Callback<Input = (AttestationObject, CollectedClientData)>
            + Clone
            + Send
            + Sync
            + 'static,
    {
        // Abort any prior register/sign calls.
        self.cancel();
        let cbc = callback.clone();

        let transaction = Transaction::new(timeout, cbc.clone(), move |info, _alive| {
            // TODO(baloo): what is alive about? have to ask jcj
            // Create a new device.
            let dev = &mut match Device::new(info) {
                Ok(dev) => dev,
                Err(e) => {
                    info!("error happened with device: {}", e);
                    return;
                }
            };

            // Try initializing it.
            if let Err(e) = dev.init() {
                info!("error while initializing device: {}", e);
                return;
            }

            // TODO(baloo): not sure about this, have to ask
            // We currently support none of the authenticator selection
            // criteria because we can't ask tokens whether they do support
            // those features. If flags are set, ignore all tokens for now.
            //
            // Technically, this is a ConstraintError because we shouldn't talk
            // to this authenticator in the first place. But the result is the
            // same anyway.
            //if !flags.is_empty() {
            //    return;
            //}

            // TODO(baloo): not sure about this, have to ask
            // Iterate the exclude list and see if there are any matches.
            // If so, we'll keep polling the device anyway to test for user
            // consent, to be consistent with CTAP2 device behavior.
            //let excluded = key_handles.iter().any(|key_handle| {
            //    is_valid_transport(key_handle.transports)
            //        && u2f_is_keyhandle_valid(dev, &challenge, &application, &key_handle.credential)
            //            .unwrap_or(false) /* no match on failure */
            //});

            let resp = dev.send_msg(&params);
            match resp {
                Ok(resp) => callback.call(Ok(resp)),
                Err(ref e) if e.device_unsupported() || e.unsupported_command() => {}
                Err(Error::Command(ref e)) if e.device_busy() => {}
                Err(e) => {
                    warn!("error happened: {}", e);
                    callback.call(Err(::Error::Unknown));
                }
            }
        });

        self.transaction = Some(try_or!(transaction, |e| cbc.call(Err(e))));
    }

    pub fn sign<CB>(&mut self, timeout: u64, command: GetAssertion, callback: CB)
    where
        CB: Callback<Input = AssertionObject> + Clone + Send + Sync + 'static,
    {
        // Abort any prior register/sign calls.
        self.cancel();

        let cbc = callback.clone();

        let transaction = Transaction::new(timeout, callback.clone(), move |info, alive| {
            // TODO(baloo): what is alive about? have to ask jcj
            // Create a new device.
            let dev = &mut match Device::new(info) {
                Ok(dev) => dev,
                Err(e) => {
                    info!("error happened with device: {}", e);
                    return;
                }
            };

            // Try initializing it.
            if let Err(e) = dev.init() {
                info!("error while initializing device: {}", e);
                return;
            }

            let resp = dev.send_msg(&command);
            match resp {
                Ok(resp) => callback.call(Ok(resp)),
                // TODO(baloo): if key_handle is invalid for this device, it
                //              should reply something like:
                //              CTAP2_ERR_INVALID_CREDENTIAL
                //              have to check
                Err(ref e) if e.device_unsupported() || e.unsupported_command() => {}
                Err(Error::Command(ref e)) if e.device_busy() => {}
                Err(e) => {
                    warn!("error happened: {}", e);
                    callback.call(Err(::Error::Unknown));
                }
            }
        });

        self.transaction = Some(try_or!(transaction, move |e| cbc.call(Err(e))));
    }

    // This blocks.
    pub fn cancel(&mut self) {
        if let Some(mut transaction) = self.transaction.take() {
            transaction.cancel();
        }
    }
}
