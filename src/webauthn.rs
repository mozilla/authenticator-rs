/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io;
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::time::Duration;

use crate::ctap::{Challenge, CollectedClientData, Origin, WebauthnType};
use crate::ctap2::attestation::AttestationObject;
use crate::ctap2::commands::{
    AssertionObject, GetAssertion, MakeCredentials, MakeCredentialsOptions, Pin,
};
use crate::ctap2::server::{PublicKeyCredentialParameters, RelyingParty, RelyingPartyData, User};
#[cfg(test)]
use crate::transport::platform::TestCase;
use crate::SignFlags;
use consts::PARAMETER_SIZE;
use runloop::RunLoop;
use statemachine::StateMachine;
use util::{OnceCallback, OnceCallbackMap};

enum QueueAction {
    Register {
        timeout: u64,
        params: MakeCredentials,
        callback: OnceCallback<(AttestationObject, CollectedClientData)>,
    },
    Sign {
        timeout: u64,
        command: GetAssertion,
        callback: OnceCallbackMap<AssertionObject, ::SignResult>,
    },
    Cancel,
}

pub(crate) enum Capability {
    Fido2 = 2,
}

pub struct Manager {
    queue: RunLoop,
    tx: Sender<QueueAction>,
    filter: Option<Capability>,
}

impl Manager {
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
                    Ok(QueueAction::Sign {
                        timeout,
                        command,
                        callback,
                    }) => {
                        // This must not block, otherwise we can't cancel.
                        sm.sign(timeout, command, callback);
                    }
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

        let rp = RelyingParty::Data(RelyingPartyData { id: relying_party });
        let origin = Origin::Some(origin);

        let client_data = CollectedClientData {
            type_: WebauthnType::Create,
            challenge: challenge.clone().into(),
            origin,
            token_binding: None,
        };

        let register = MakeCredentials::new(
            client_data,
            rp,
            Some(user),
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

    pub fn sign<F>(
        &self,
        flags: SignFlags,
        timeout: u64,
        challenge: Vec<u8>,
        app_ids: Vec<::AppId>,
        key_handles: Vec<::KeyHandle>,
        callback: F,
    ) -> Result<(), ::Error>
    where
        F: FnOnce(Result<::SignResult, ::Error>),
        F: Send + 'static,
    {
        if challenge.len() != PARAMETER_SIZE {
            return Err(::Error::Unknown);
        }

        let challenge = Challenge::from(challenge);
        let callback = OnceCallback::new(callback);

        if app_ids.is_empty() {
            return Err(::Error::Unknown);
        }

        let client_data = CollectedClientData {
            type_: WebauthnType::Get,
            challenge,
            origin: Origin::None,
            token_binding: None,
        };

        // TODO(baloo): This block of code and commend was previously in src/statemanchine.rs
        //              I moved this logic here, and I'm not quite sure about what we
        //              should do, have to ask jcj
        //
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
        let options = MakeCredentialsOptions {
            user_validation: flags.contains(SignFlags::REQUIRE_USER_VERIFICATION),
            ..MakeCredentialsOptions::default()
        };

        for app_id in &app_ids {
            for key_handle in &key_handles {
                if key_handle.credential.len() > 256 {
                    return Err(::Error::Unknown);
                }
                let rp = RelyingParty::new_hash(app_id).map_err(|_| ::Error::Unknown)?;

                let allow_list = vec![key_handle.into()];

                let command =
                    GetAssertion::new(client_data.clone(), rp, allow_list, Some(options), None);

                let app_id = app_id.clone();
                let key_handle = key_handle.credential.clone();
                let callback = callback.clone();

                let callback = callback.map(move |assertion_object: AssertionObject| {
                    (app_id, key_handle, assertion_object.u2f_sign_data())
                });

                let action = QueueAction::Sign {
                    command,
                    timeout,
                    callback,
                };
                self.tx.send(action).map_err(|_| ::Error::Unknown)?;
            }
        }
        Ok(())
    }

    pub fn cancel(&self) -> Result<(), ::Error> {
        self.tx
            .send(QueueAction::Cancel)
            .map_err(|_| ::Error::Unknown)
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.queue.cancel();
    }
}
