/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::util::StateCallback;

pub struct Transaction {}

impl Transaction {
    pub fn new<F, T>(
        timeout: u64,
        callback: StateCallback<Result<T, crate::Error>>,
        new_device_cb: F,
    ) -> Result<Self, crate::Error>
    where
        F: Fn(String, &dyn Fn() -> bool),
    {
        callback.call(Err(crate::Error::NotSupported));
        Err(crate::Error::NotSupported)
    }

    pub fn cancel(&mut self) {
        /* No-op. */
    }
}
