/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::authenticatorservice::AuthenticatorTransport;
use crate::authenticatorservice::{RegisterArgs, RegisterArgsCtap1, SignArgs};
use crate::consts::PARAMETER_SIZE;
use crate::ctap2::client_data::{CollectedClientData, WebauthnType};
use crate::ctap2::commands::get_assertion::{GetAssertion, GetAssertionOptions};
use crate::ctap2::commands::make_credentials::MakeCredentials;
use crate::ctap2::commands::make_credentials::MakeCredentialsOptions;
use crate::ctap2::server::RelyingParty;
use crate::errors::*;
use crate::statecallback::StateCallback;
use crate::statemachine::{StateMachine, StateMachineCtap2};
use crate::SignFlags;
use runloop::RunLoop;
use std::io;
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::time::Duration;

enum QueueAction {
    RegisterCtap1 {
        timeout: u64,
        ctap_args: RegisterArgsCtap1,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::RegisterResult>>,
    },
    RegisterCtap2 {
        timeout: u64,
        make_credentials: MakeCredentials,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::RegisterResult>>,
    },
    SignCtap1 {
        flags: crate::SignFlags,
        timeout: u64,
        challenge: Vec<u8>,
        app_ids: Vec<crate::AppId>,
        key_handles: Vec<crate::KeyHandle>,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::SignResult>>,
    },
    SignCtap2 {
        timeout: u64,
        get_assertion: GetAssertion,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::SignResult>>,
    },
    Cancel,
}

pub struct U2FManager {
    queue: RunLoop,
    tx: Sender<QueueAction>,
}

impl U2FManager {
    pub fn new() -> io::Result<Self> {
        let (tx, rx) = channel();

        // Start a new work queue thread.
        let queue = RunLoop::new(move |alive| {
            let mut sm = StateMachine::new();

            while alive() {
                match rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(QueueAction::RegisterCtap1 {
                        timeout,
                        ctap_args,
                        status,
                        callback,
                    }) => {
                        // This must not block, otherwise we can't cancel.
                        sm.register(
                            ctap_args.flags,
                            timeout,
                            ctap_args.challenge,
                            ctap_args.application,
                            ctap_args.key_handles,
                            status,
                            callback,
                        );
                    }
                    Ok(QueueAction::SignCtap1 {
                        flags,
                        timeout,
                        challenge,
                        app_ids,
                        key_handles,
                        status,
                        callback,
                    }) => {
                        // This must not block, otherwise we can't cancel.
                        sm.sign(
                            flags,
                            timeout,
                            challenge,
                            app_ids,
                            key_handles,
                            status,
                            callback,
                        );
                    }
                    Ok(QueueAction::Cancel) => {
                        // Cancelling must block so that we don't start a new
                        // polling thread before the old one has shut down.
                        sm.cancel();
                    }
                    Ok(QueueAction::RegisterCtap2 { .. }) => {
                        // TODO(MS): What to do here? Error out? Silently ignore?
                        unimplemented!();
                    }
                    Ok(QueueAction::SignCtap2 { .. }) => {
                        // TODO(MS): What to do here? Error out? Silently ignore?
                        unimplemented!();
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

        Ok(Self { queue, tx })
    }
}

impl AuthenticatorTransport for U2FManager {
    fn register(
        &mut self,
        timeout: u64,
        ctap_args: RegisterArgs,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::RegisterResult>>,
    ) -> crate::Result<()> {
        let args = match ctap_args {
            RegisterArgs::CTAP1(args) => args,
            RegisterArgs::CTAP2(_) => {
                return Err(AuthenticatorError::VersionMismatch("U2FManager", 1));
            }
        };
        if args.challenge.len() != PARAMETER_SIZE || args.application.len() != PARAMETER_SIZE {
            return Err(AuthenticatorError::InvalidRelyingPartyInput);
        }

        for key_handle in &args.key_handles {
            if key_handle.credential.len() > 256 {
                return Err(AuthenticatorError::InvalidRelyingPartyInput);
            }
        }

        let action = QueueAction::RegisterCtap1 {
            timeout,
            ctap_args: args,
            status,
            callback,
        };
        Ok(self.tx.send(action)?)
    }

    fn sign(
        &mut self,
        timeout: u64,
        ctap_args: SignArgs,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::SignResult>>,
    ) -> crate::Result<()> {
        let args = match ctap_args {
            SignArgs::CTAP1(args) => args,
            SignArgs::CTAP2(_) => {
                return Err(AuthenticatorError::VersionMismatch("U2FManager", 1));
            }
        };

        if args.challenge.len() != PARAMETER_SIZE {
            return Err(AuthenticatorError::InvalidRelyingPartyInput);
        }

        if args.app_ids.is_empty() {
            return Err(AuthenticatorError::InvalidRelyingPartyInput);
        }

        for app_id in &args.app_ids {
            if app_id.len() != PARAMETER_SIZE {
                return Err(AuthenticatorError::InvalidRelyingPartyInput);
            }
        }

        for key_handle in &args.key_handles {
            if key_handle.credential.len() > 256 {
                return Err(AuthenticatorError::InvalidRelyingPartyInput);
            }
        }

        let action = QueueAction::SignCtap1 {
            flags: args.flags,
            timeout,
            challenge: args.challenge,
            app_ids: args.app_ids,
            key_handles: args.key_handles,
            status,
            callback,
        };
        Ok(self.tx.send(action)?)
    }

    fn cancel(&mut self) -> crate::Result<()> {
        Ok(self.tx.send(QueueAction::Cancel)?)
    }
}

impl Drop for U2FManager {
    fn drop(&mut self) {
        self.queue.cancel();
    }
}

pub struct Manager {
    queue: RunLoop,
    tx: Sender<QueueAction>,
}

impl Manager {
    pub fn new() -> io::Result<Self> {
        let (tx, rx) = channel();

        // Start a new work queue thread.
        let queue = RunLoop::new(move |alive| {
            let mut sm = StateMachineCtap2::new();

            while alive() {
                match rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(QueueAction::RegisterCtap2 {
                        timeout,
                        make_credentials,
                        status,
                        callback,
                    }) => {
                        // This must not block, otherwise we can't cancel.
                        sm.register(timeout, make_credentials, status, callback);
                    }
                    Ok(QueueAction::RegisterCtap1 {
                        timeout: _,
                        ctap_args: _,
                        status: _,
                        callback: _,
                    }) => {
                        // TODO(MS): Repackage CTAP1 info into MakeCredentials.
                        // Only until U2FManager is deleted, then this repackaging probably makes more sense
                        // when creating QueueAction::RegisterCtap1.
                        unimplemented!();
                    }

                    Ok(QueueAction::SignCtap1 {
                        timeout: _,
                        callback: _,
                        flags: _,
                        challenge: _,
                        app_ids: _,
                        key_handles: _,
                        status: _,
                    }) => {
                        // This must not block, otherwise we can't cancel.
                        // sm.sign(timeout, command, callback);
                    }

                    Ok(QueueAction::SignCtap2 {
                        timeout,
                        get_assertion,
                        status,
                        callback,
                    }) => {
                        // This must not block, otherwise we can't cancel.
                        sm.sign(timeout, get_assertion, status, callback);
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

        Ok(Self { queue, tx })
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.queue.cancel();
    }
}

impl AuthenticatorTransport for Manager {
    fn register(
        &mut self,
        timeout: u64,
        ctap_args: RegisterArgs,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::RegisterResult>>,
    ) -> Result<(), AuthenticatorError> {
        let args = match ctap_args {
            RegisterArgs::CTAP2(args) => args,
            RegisterArgs::CTAP1(_) => {
                // TODO(MS): Implement the backwards compatible ctap1 registration using MakeCredentials
                unimplemented!();
            }
        };

        let client_data = CollectedClientData {
            webauthn_type: WebauthnType::Create,
            challenge: args.challenge.into(),
            origin: args.origin,
            cross_origin: None,
            token_binding: None,
        };

        let make_credentials = MakeCredentials::new(
            client_data,
            args.relying_party,
            Some(args.user),
            args.pub_cred_params,
            args.exclude_list,
            MakeCredentialsOptions {
                resident_key: None,
                user_validation: None,
            },
            args.pin,
            // pin_auth will be filled in Statemachine, once we have a device
        );

        let action = QueueAction::RegisterCtap2 {
            timeout,
            make_credentials,
            status,
            callback,
        };
        Ok(self.tx.send(action)?)
    }

    fn sign(
        &mut self,
        timeout: u64,
        ctap_args: SignArgs,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::SignResult>>,
    ) -> crate::Result<()> {
        let args = match ctap_args {
            SignArgs::CTAP1(_args) => {
                // TODO(MS): Implement the backwards compatible ctap1 registration using MakeCredentials
                unimplemented!();
            }
            SignArgs::CTAP2(args) => args,
        };

        let client_data = CollectedClientData {
            webauthn_type: WebauthnType::Create,
            challenge: args.challenge.into(),
            origin: args.origin,
            cross_origin: None,
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
        let options = if args.flags == SignFlags::empty() {
            GetAssertionOptions {
                user_validation: None,
                user_presence: None,
            }
        } else {
            GetAssertionOptions {
                user_validation: Some(args.flags.contains(SignFlags::REQUIRE_USER_VERIFICATION)),
                ..GetAssertionOptions::default()
            }
        };

        let get_assertion = GetAssertion::new(
            client_data.clone(),
            RelyingParty {
                id: args.relying_party_id,
                name: None,
                icon: None,
            },
            args.allow_list,
            options,
            args.pin,
        );

        let action = QueueAction::SignCtap2 {
            timeout,
            get_assertion,
            status,
            callback,
        };
        self.tx.send(action)?;

        Ok(())
    }

    fn cancel(&mut self) -> Result<(), AuthenticatorError> {
        Ok(self.tx.send(QueueAction::Cancel)?)
    }
}
