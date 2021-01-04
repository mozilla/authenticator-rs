/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use runloop::RunLoop;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::{io, thread};

use crate::authenticatorservice::AuthenticatorTransport;
use crate::errors;
use crate::statecallback::StateCallback;
use crate::virtualdevices::dbus::dbus;

pub struct VirtualManager {
    state: Arc<Mutex<dbus::DeviceManagerState<'static>>>,
    rloop: Option<RunLoop>,
}

impl VirtualManager {
    pub fn new() -> io::Result<Self> {
        let connection = zbus::Connection::new_session().unwrap();
        let connectionclone = connection.clone();

        let state = dbus::DeviceManagerState::new();
        let stateclone = state.clone();

        let builder = thread::Builder::new().name("D-Bus Signal Receiver".into());
        builder.spawn(move || dbus::serve(stateclone, connectionclone))?;

        Ok(Self { state, rloop: None })
    }
}

impl AuthenticatorTransport for VirtualManager {
    fn register(
        &mut self,
        _flags: crate::RegisterFlags,
        timeout: u64,
        challenge: Vec<u8>,
        application: crate::AppId,
        _key_handles: Vec<crate::KeyHandle>,
        _status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::RegisterResult>>,
    ) -> crate::Result<()> {
        // Abort any prior register/sign calls.
        self.cancel()?;

        let state = self.state.clone();
        let rloop = try_or!(
            RunLoop::new_with_timeout(
                move |alive| {
                    while alive() {
                        let state_obj = state.lock().unwrap();

                        for device in &*state_obj.devices {
                            let register_result = device.register(challenge, application);
                            thread::spawn(move || {
                                callback.call(register_result);
                            });
                            return;
                        }
                    }
                },
                timeout
            ),
            |_| Err(errors::AuthenticatorError::Platform)
        );

        self.rloop = Some(rloop);
        Ok(())
    }

    fn sign(
        &mut self,
        _flags: crate::SignFlags,
        timeout: u64,
        challenge: Vec<u8>,
        app_ids: Vec<crate::AppId>,
        key_handles: Vec<crate::KeyHandle>,
        _status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::SignResult>>,
    ) -> crate::Result<()> {
        // Abort any prior register/sign calls.
        self.cancel()?;

        let state = self.state.clone();
        let app_ids = app_ids.clone();
        let key_handles = key_handles.clone();
        let rloop = try_or!(
            RunLoop::new_with_timeout(
                move |alive| {
                    while alive() {
                        let state_obj = state.lock().unwrap();

                        for (index, app_id) in app_ids.iter().enumerate() {
                            for device in &*state_obj.devices {
                                let sign_result = device.sign(
                                    challenge,
                                    app_id.clone(),
                                    key_handles[index].credential.clone(),
                                );
                                thread::spawn(move || {
                                    callback.call(sign_result);
                                });
                                return;
                            }
                        }
                    }
                },
                timeout
            ),
            |_| Err(errors::AuthenticatorError::Platform)
        );

        self.rloop = Some(rloop);
        Ok(())
    }

    fn cancel(&mut self) -> crate::Result<()> {
        if let Some(r) = self.rloop.take() {
            debug!("D-Bus operation cancelled.");
            r.cancel();
        }
        Ok(())
    }
}
