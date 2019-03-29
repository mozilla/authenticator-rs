/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io;
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::time::Duration;

use crate::ctap::{CollectedClientData, WebauthnType};
use crate::ctap2::attestation::AttestationObject;
use crate::ctap2::commands::{MakeCredentials, Pin};
use crate::ctap2::server::{PublicKeyCredentialParameters, RelyingParty, User};
//use consts::PARAMETER_SIZE;
use runloop::RunLoop;
use statemachine::StateMachine;
use util::OnceCallback;
#[cfg(test)]
use crate::transport::platform::TestCase;


enum QueueAction {
    Register {
        timeout: u64,
        params: MakeCredentials,
        callback: OnceCallback<(AttestationObject, CollectedClientData)>,
    },
    //Sign {
    //    flags: ::SignFlags,
    //    timeout: u64,
    //    challenge: Vec<u8>,
    //    app_ids: Vec<::AppId>,
    //    key_handles: Vec<::KeyHandle>,
    //    callback: OnceCallback<::SignResult>,
    //},
    Cancel,
}

pub(crate) enum Capability {
    Fido2 = 2,
}

pub struct FidoManager {
    queue: RunLoop,
    tx: Sender<QueueAction>,
    filter: Option<Capability>,
}

impl FidoManager {
    pub fn new() -> io::Result<Self> {
        let (tx, rx) = channel();

        // Tests case injection works with thread local storage values,
        // this looks up the value, and reinject it inside the new thread.
        // This is only enabled for tests
        #[cfg(test)]
        let value = TestCase::active();

        // Start a new work queue thread.
        let queue = RunLoop::new(move |alive| {
            #[cfg(test)]
            TestCase::activate(value);

            let mut sm = StateMachine::new();

            while alive() {
                match rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(QueueAction::Register {
                        timeout,
                        params,
                        callback,
                    }) => {
                        // This must not block, otherwise we can't cancel.
                        sm.register(timeout, params, callback);
                    }
                    //Ok(QueueAction::Sign {
                    //    flags,
                    //    timeout,
                    //    challenge,
                    //    app_ids,
                    //    key_handles,
                    //    callback,
                    //}) => {
                    //    // This must not block, otherwise we can't cancel.
                    //    sm.sign(flags, timeout, challenge, app_ids, key_handles, callback);
                    //}
                    Ok(QueueAction::Cancel) => {
                        // Cancelling must block so that we don't start a new
                        // polling thread before the old one has shut down.
                        sm.cancel();
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        break;
                    }
                    _ => { /* continue */ }
                }
            }

            // Cancel any ongoing activity.
            sm.cancel();
        })?;

        Ok(Self {
            queue,
            tx,
            filter: None,
        })
    }

    pub fn fido2_capable(&mut self) {
        self.filter = Some(Capability::Fido2);
    }

    pub fn register<F>(
        &self,
        relying_party: String,
        origin: String,
        timeout: u64,
        challenge: Vec<u8>,
        user: User,
        pub_cred_params: Vec<PublicKeyCredentialParameters>,
        pin: Option<Pin>,
        callback: F,
    ) -> Result<(), ::Error>
    where
        F: FnOnce(Result<(AttestationObject, CollectedClientData), ::Error>),
        F: Send + 'static,
    {
        //if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
        //    return Err(::Error::Unknown);
        //}

        //for key_handle in &key_handles {
        //    if key_handle.credential.len() > 256 {
        //        return Err(::Error::Unknown);
        //    }
        //}

        let callback = OnceCallback::new(callback);

        let rp = RelyingParty { id: relying_party };

        let client_data = CollectedClientData {
            type_: WebauthnType::Create,
            challenge: challenge.clone().into(),
            origin,
            token_binding: None,
        };

        let register = MakeCredentials::new(
            client_data,
            rp,
            user,
            pub_cred_params.clone(),
            Vec::new(),
            None,
            pin,
        );

        let action = QueueAction::Register {
            timeout,
            params: register,
            callback,
        };
        self.tx.send(action).map_err(|_| ::Error::Unknown)
    }

    //pub fn sign<F>(
    //    &self,
    //    flags: ::SignFlags,
    //    timeout: u64,
    //    challenge: Vec<u8>,
    //    app_ids: Vec<::AppId>,
    //    key_handles: Vec<::KeyHandle>,
    //    callback: F,
    //) -> Result<(), ::Error>
    //where
    //    F: FnOnce(Result<::SignResult, ::Error>),
    //    F: Send + 'static,
    //{
    //    if challenge.len() != PARAMETER_SIZE {
    //        return Err(::Error::Unknown);
    //    }

    //    if app_ids.is_empty() {
    //        return Err(::Error::Unknown);
    //    }

    //    for app_id in &app_ids {
    //        if app_id.len() != PARAMETER_SIZE {
    //            return Err(::Error::Unknown);
    //        }
    //    }

    //    for key_handle in &key_handles {
    //        if key_handle.credential.len() > 256 {
    //            return Err(::Error::Unknown);
    //        }
    //    }

    //    let callback = OnceCallback::new(callback);
    //    let action = QueueAction::Sign {
    //        flags,
    //        timeout,
    //        challenge,
    //        app_ids,
    //        key_handles,
    //        callback,
    //    };
    //    self.tx.send(action).map_err(|_| ::Error::Unknown)
    //}

    pub fn cancel(&self) -> Result<(), ::Error> {
        self.tx
            .send(QueueAction::Cancel)
            .map_err(|_| ::Error::Unknown)
    }
}

impl Drop for FidoManager {
    fn drop(&mut self) {
        self.queue.cancel();
    }
}

#[deprecated]
/// U2FManager has been renamed to FidoManager and you are suggested to
/// change references for compatibility
pub type U2FManager = FidoManager;
