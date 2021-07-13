/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::consts::PARAMETER_SIZE;
use crate::ctap2::commands::get_assertion::{GetAssertion, GetAssertionResult};
use crate::ctap2::commands::make_credentials::{MakeCredentials, MakeCredentialsResult};
use crate::ctap2::commands::{CommandError, PinAuthCommand, StatusCode};
use crate::errors::{self, AuthenticatorError};
use crate::statecallback::StateCallback;
use crate::transport::platform::{device::Device, transaction::Transaction};
use crate::transport::{errors::HIDError, FidoDevice, Nonce};
use crate::u2fprotocol::{u2f_init_device, u2f_is_keyhandle_valid, u2f_register, u2f_sign};
use crate::u2ftypes::U2FDevice;
use crate::{RegisterResult, SignResult};
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

fn is_valid_transport(transports: crate::AuthenticatorTransports) -> bool {
    transports.is_empty() || transports.contains(crate::AuthenticatorTransports::USB)
}

fn find_valid_key_handles<'a, F>(
    app_ids: &'a [crate::AppId],
    key_handles: &'a [crate::KeyHandle],
    mut is_valid: F,
) -> (&'a crate::AppId, Vec<&'a crate::KeyHandle>)
where
    F: FnMut(&Vec<u8>, &crate::KeyHandle) -> bool,
{
    // Try all given app_ids in order.
    for app_id in app_ids {
        // Find all valid key handles for the current app_id.
        let valid_handles = key_handles
            .iter()
            .filter(|key_handle| is_valid(app_id, key_handle))
            .collect::<Vec<_>>();

        // If there's at least one, stop.
        if !valid_handles.is_empty() {
            return (app_id, valid_handles);
        }
    }

    (&app_ids[0], vec![])
}

fn send_status(status_mutex: &Mutex<Sender<crate::StatusUpdate>>, msg: crate::StatusUpdate) {
    match status_mutex.lock() {
        Ok(s) => match s.send(msg) {
            Ok(_) => {}
            Err(e) => error!("Couldn't send status: {:?}", e),
        },
        Err(e) => {
            error!("Couldn't obtain status mutex: {:?}", e);
        }
    };
}

#[derive(Default)]
pub struct StateMachine {
    transaction: Option<Transaction>,
}

impl StateMachine {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn register(
        &mut self,
        flags: crate::RegisterFlags,
        timeout: u64,
        challenge: Vec<u8>,
        application: crate::AppId,
        key_handles: Vec<crate::KeyHandle>,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::RegisterResult>>,
    ) {
        // Abort any prior register/sign calls.
        self.cancel();

        let cbc = callback.clone();
        let status_mutex = Mutex::new(status);

        let transaction = Transaction::new(timeout, cbc.clone(), move |info, alive| {
            // Create a new device.
            let dev = &mut match Device::new(info) {
                Ok(dev) => dev,
                _ => return,
            };

            // Try initializing it.
            if !dev.is_u2f() || !u2f_init_device(dev) {
                return;
            }

            // We currently support none of the authenticator selection
            // criteria because we can't ask tokens whether they do support
            // those features. If flags are set, ignore all tokens for now.
            //
            // Technically, this is a ConstraintError because we shouldn't talk
            // to this authenticator in the first place. But the result is the
            // same anyway.
            if !flags.is_empty() {
                return;
            }

            send_status(
                &status_mutex,
                crate::StatusUpdate::DeviceAvailable {
                    dev_info: dev.get_device_info(),
                },
            );

            // Iterate the exclude list and see if there are any matches.
            // If so, we'll keep polling the device anyway to test for user
            // consent, to be consistent with CTAP2 device behavior.
            let excluded = key_handles.iter().any(|key_handle| {
                is_valid_transport(key_handle.transports)
                    && u2f_is_keyhandle_valid(dev, &challenge, &application, &key_handle.credential)
                        .unwrap_or(false) /* no match on failure */
            });

            while alive() {
                if excluded {
                    let blank = vec![0u8; PARAMETER_SIZE];
                    if u2f_register(dev, &blank, &blank).is_ok() {
                        callback.call(Err(errors::AuthenticatorError::U2FToken(
                            errors::U2FTokenError::InvalidState,
                        )));
                        break;
                    }
                } else if let Ok(bytes) = u2f_register(dev, &challenge, &application) {
                    let dev_info = dev.get_device_info();
                    send_status(
                        &status_mutex,
                        crate::StatusUpdate::Success {
                            dev_info: dev.get_device_info(),
                        },
                    );
                    callback.call(Ok(RegisterResult::CTAP1(bytes, dev_info)));
                    break;
                }

                // Sleep a bit before trying again.
                thread::sleep(Duration::from_millis(100));
            }

            send_status(
                &status_mutex,
                crate::StatusUpdate::DeviceUnavailable {
                    dev_info: dev.get_device_info(),
                },
            );
        });

        self.transaction = Some(try_or!(transaction, |e| cbc.call(Err(e))));
    }

    pub fn sign(
        &mut self,
        flags: crate::SignFlags,
        timeout: u64,
        challenge: Vec<u8>,
        app_ids: Vec<crate::AppId>,
        key_handles: Vec<crate::KeyHandle>,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::SignResult>>,
    ) {
        // Abort any prior register/sign calls.
        self.cancel();

        let cbc = callback.clone();

        let status_mutex = Mutex::new(status);

        let transaction = Transaction::new(timeout, cbc.clone(), move |info, alive| {
            // Create a new device.
            let dev = &mut match Device::new(info) {
                Ok(dev) => dev,
                _ => return,
            };

            // Try initializing it.
            if !dev.is_u2f() || !u2f_init_device(dev) {
                return;
            }

            // We currently don't support user verification because we can't
            // ask tokens whether they do support that. If the flag is set,
            // ignore all tokens for now.
            //
            // Technically, this is a ConstraintError because we shouldn't talk
            // to this authenticator in the first place. But the result is the
            // same anyway.
            if !flags.is_empty() {
                return;
            }

            // For each appId, try all key handles. If there's at least one
            // valid key handle for an appId, we'll use that appId below.
            let (app_id, valid_handles) =
                find_valid_key_handles(&app_ids, &key_handles, |app_id, key_handle| {
                    u2f_is_keyhandle_valid(dev, &challenge, app_id, &key_handle.credential)
                        .unwrap_or(false) /* no match on failure */
                });

            // Aggregate distinct transports from all given credentials.
            let transports = key_handles
                .iter()
                .fold(crate::AuthenticatorTransports::empty(), |t, k| {
                    t | k.transports
                });

            // We currently only support USB. If the RP specifies transports
            // and doesn't include USB it's probably lying.
            if !is_valid_transport(transports) {
                return;
            }

            send_status(
                &status_mutex,
                crate::StatusUpdate::DeviceAvailable {
                    dev_info: dev.get_device_info(),
                },
            );

            'outer: while alive() {
                // If the device matches none of the given key handles
                // then just make it blink with bogus data.
                if valid_handles.is_empty() {
                    let blank = vec![0u8; PARAMETER_SIZE];
                    if u2f_register(dev, &blank, &blank).is_ok() {
                        callback.call(Err(errors::AuthenticatorError::U2FToken(
                            errors::U2FTokenError::InvalidState,
                        )));
                        break;
                    }
                } else {
                    // Otherwise, try to sign.
                    for key_handle in &valid_handles {
                        if let Ok(bytes) = u2f_sign(dev, &challenge, app_id, &key_handle.credential)
                        {
                            let dev_info = dev.get_device_info();
                            send_status(
                                &status_mutex,
                                crate::StatusUpdate::Success {
                                    dev_info: dev.get_device_info(),
                                },
                            );
                            callback.call(Ok(SignResult::CTAP1(
                                app_id.clone(),
                                key_handle.credential.clone(),
                                bytes,
                                dev_info,
                            )));
                            break 'outer;
                        }
                    }
                }

                // Sleep a bit before trying again.
                thread::sleep(Duration::from_millis(100));
            }

            send_status(
                &status_mutex,
                crate::StatusUpdate::DeviceUnavailable {
                    dev_info: dev.get_device_info(),
                },
            );
        });

        self.transaction = Some(try_or!(transaction, |e| cbc.call(Err(e))));
    }

    // This blocks.
    pub fn cancel(&mut self) {
        if let Some(mut transaction) = self.transaction.take() {
            transaction.cancel();
        }
    }
}

#[derive(Default)]
// TODO(MS): To be renamed to `StateMachine` once U2FManager and the original StateMachine can be removed.
pub struct StateMachineCtap2 {
    transaction: Option<Transaction>,
}

impl StateMachineCtap2 {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn register(
        &mut self,
        timeout: u64,
        params: MakeCredentials,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::RegisterResult>>,
    ) {
        // Abort any prior register/sign calls.
        self.cancel();
        let cbc = callback.clone();
        let status_mutex = Mutex::new(status);
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
            if let Err(e) = dev.init(Nonce::CreateRandom) {
                warn!("error while initializing device: {}", e);
                return;
            }
            send_status(
                &status_mutex,
                crate::StatusUpdate::DeviceAvailable {
                    dev_info: dev.get_device_info(),
                },
            );
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

            // TODO(MS): This is wasteful, but the current setup with read only-functions doesn't allow me
            //           to modify "params" directly.
            let mut makecred = params.clone();
            match makecred.determine_pin_auth(dev) {
                Ok(x) => x,
                Err(e) => {
                    callback.call(Err(errors::AuthenticatorError::HIDError(e)));
                    return;
                }
            };

            debug!("------------------------------------------------------------------");
            debug!("{:?}", makecred);
            debug!("------------------------------------------------------------------");
            let resp = dev.send_msg(&makecred);
            if resp.is_ok() {
                send_status(
                    &status_mutex,
                    crate::StatusUpdate::Success {
                        dev_info: dev.get_device_info(),
                    },
                );
            }
            match resp {
                Ok(MakeCredentialsResult::CTAP2(attestation, client_data)) => {
                    callback.call(Ok(RegisterResult::CTAP2(attestation, client_data)))
                }
                Ok(MakeCredentialsResult::CTAP1(data)) => {
                    callback.call(Ok(RegisterResult::CTAP1(data, dev.get_device_info())))
                }

                Err(HIDError::DeviceNotSupported) | Err(HIDError::UnsupportedCommand) => {}
                Err(HIDError::Command(CommandError::StatusCode(StatusCode::ChannelBusy, _))) => {}
                Err(e) => {
                    warn!("error happened: {}", e);
                    callback.call(Err(AuthenticatorError::HIDError(e)));
                }
            }
            send_status(
                &status_mutex,
                crate::StatusUpdate::DeviceUnavailable {
                    dev_info: dev.get_device_info(),
                },
            );
        });

        self.transaction = Some(try_or!(transaction, |e| cbc.call(Err(e))));
    }

    pub fn sign(
        &mut self,
        timeout: u64,
        params: GetAssertion,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::SignResult>>,
    ) {
        // Abort any prior register/sign calls.
        self.cancel();
        let cbc = callback.clone();
        let status_mutex = Mutex::new(status);

        let transaction = Transaction::new(timeout, callback.clone(), move |info, _alive| {
            let dev = &mut match Device::new(info) {
                Ok(dev) => dev,
                Err(e) => {
                    info!("error happened with device: {}", e);
                    return;
                }
            };

            // Try initializing it.
            if let Err(e) = dev.init(Nonce::CreateRandom) {
                warn!("error while initializing device: {}", e);
                return;
            }
            send_status(
                &status_mutex,
                crate::StatusUpdate::DeviceAvailable {
                    dev_info: dev.get_device_info(),
                },
            );

            // TODO(MS): This is wasteful, but the current setup with read only-functions doesn't allow me
            //           to modify "params" directly.
            let mut getassertion = params.clone();
            match getassertion.determine_pin_auth(dev) {
                Ok(x) => x,
                Err(e) => {
                    callback.call(Err(errors::AuthenticatorError::HIDError(e)));
                    return;
                }
            };

            debug!("------------------------------------------------------------------");
            debug!("{:?}", getassertion);
            debug!("------------------------------------------------------------------");

            let resp = dev.send_msg(&getassertion);
            match resp {
                Ok(GetAssertionResult::CTAP1(resp)) => {
                    let app_id = getassertion.rp.hash().as_ref().to_vec();
                    let key_handle = getassertion.allow_list[0].id.clone();

                    callback.call(Ok(SignResult::CTAP1(
                        app_id,
                        key_handle,
                        resp,
                        dev.get_device_info(),
                    )))
                }
                Ok(GetAssertionResult::CTAP2(resp)) => callback.call(Ok(SignResult::CTAP2(resp))),
                // TODO(baloo): if key_handle is invalid for this device, it
                //              should reply something like:
                //              CTAP2_ERR_INVALID_CREDENTIAL
                //              have to check
                Err(HIDError::DeviceNotSupported) | Err(HIDError::UnsupportedCommand) => {}
                Err(HIDError::Command(CommandError::StatusCode(StatusCode::ChannelBusy, _))) => {}
                Err(e) => {
                    warn!("error happened: {}", e);
                    callback.call(Err(AuthenticatorError::HIDError(e)));
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
