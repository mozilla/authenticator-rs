/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io;
use std::sync::mpsc::Sender;

use crate::authenticatorservice::AuthenticatorTransport;
use crate::util::StateCallback;

pub struct TouchIDToken {}

impl TouchIDToken {
    pub fn new() -> io::Result<Self> {
        Ok(Self {})
    }
}

impl AuthenticatorTransport for TouchIDToken {
    fn register(
        &mut self,
        _flags: crate::RegisterFlags,
        _timeout: u64,
        _challenge: Vec<u8>,
        _application: crate::AppId,
        _key_handles: Vec<crate::KeyHandle>,
        _status: Sender<crate::StatusUpdate>,
        _callback: StateCallback<Result<crate::RegisterResult, crate::Error>>,
    ) -> Result<(), crate::Error> {
        Ok(())
    }

    fn sign(
        &mut self,
        _flags: crate::SignFlags,
        _timeout: u64,
        _challenge: Vec<u8>,
        _app_ids: Vec<crate::AppId>,
        _key_handles: Vec<crate::KeyHandle>,
        _status: Sender<crate::StatusUpdate>,
        _callback: StateCallback<Result<crate::SignResult, crate::Error>>,
    ) -> Result<(), crate::Error> {
        Ok(())
    }

    fn cancel(&mut self) -> Result<(), crate::Error> {
        Ok(())
    }
}
