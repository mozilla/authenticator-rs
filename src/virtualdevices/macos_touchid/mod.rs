/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::sync::mpsc::Sender;
use std::{io, thread};

use crate::authenticatorservice::AuthenticatorTransport;
use crate::statecallback::StateCallback;
use crate::virtualdevices::software_u2f::SoftwareU2FToken;
use crate::{
    AppId, Error, KeyHandle, RegisterFlags, RegisterResult, SignFlags, SignResult, StatusUpdate,
};

pub struct TouchIDToken {
    pub u2f_impl: SoftwareU2FToken,
}

impl TouchIDToken {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            u2f_impl: SoftwareU2FToken::new(),
        })
    }
}

impl AuthenticatorTransport for TouchIDToken {
    fn register(
        &mut self,
        flags: RegisterFlags,
        timeout: u64,
        challenge: Vec<u8>,
        application: AppId,
        key_handles: Vec<KeyHandle>,
        status: Sender<StatusUpdate>,
        callback: StateCallback<Result<RegisterResult, Error>>,
    ) -> Result<(), Error> {
        let result = self
            .u2f_impl
            .register(flags, timeout, challenge, application, key_handles);
        status
            .send(StatusUpdate::Success {
                dev_info: self.u2f_impl.dev_info(),
            })
            .map_err(|_| Error::Unknown)?;
        thread::spawn(move || {
            callback.call(result);
        });
        Ok(())
    }

    fn sign(
        &mut self,
        flags: SignFlags,
        timeout: u64,
        challenge: Vec<u8>,
        app_ids: Vec<AppId>,
        key_handles: Vec<KeyHandle>,
        status: Sender<StatusUpdate>,
        callback: StateCallback<Result<SignResult, Error>>,
    ) -> Result<(), Error> {
        let result = self
            .u2f_impl
            .sign(flags, timeout, challenge, app_ids, key_handles);
        status
            .send(StatusUpdate::Success {
                dev_info: self.u2f_impl.dev_info(),
            })
            .map_err(|_| Error::Unknown)?;
        thread::spawn(move || {
            callback.call(result);
        });
        Ok(())
    }

    fn cancel(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
