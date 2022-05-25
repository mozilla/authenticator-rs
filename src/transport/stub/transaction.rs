/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::errors;
use crate::statecallback::StateCallback;
use crate::transport::device_selector::{DeviceBuildParameters, DeviceSelectorEvent};
use std::sync::mpsc::Sender;

pub struct Transaction {}

impl Transaction {
    pub fn new<F, T>(
        timeout: u64,
        callback: StateCallback<crate::Result<T>>,
        status: Sender<crate::StatusUpdate>,
        new_device_cb: F,
    ) -> crate::Result<Self>
    where
        F: Fn(
                DeviceBuildParameters,
                Sender<DeviceSelectorEvent>,
                Sender<crate::StatusUpdate>,
                &dyn Fn() -> bool,
            ) + Sync
            + Send
            + 'static,
        T: 'static,
    {
        callback.call(Err(errors::AuthenticatorError::U2FToken(
            errors::U2FTokenError::NotSupported,
        )));

        Err(errors::AuthenticatorError::U2FToken(
            errors::U2FTokenError::NotSupported,
        ))
    }

    pub fn cancel(&mut self) {
        /* No-op. */
    }
}
