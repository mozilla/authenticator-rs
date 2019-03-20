/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//use runloop::RunLoop;

use util::OnceCallback;

use super::TestCase;

pub struct Transaction {}

fn always_alive() -> bool {
    true
}

impl Transaction {
    pub fn new<F, T>(
        _timeout: u64,
        _callback: OnceCallback<T>,
        new_device_cb: F,
    ) -> Result<Self, ::Error>
    where
        F: Fn(TestCase, &Fn() -> bool) + Sync + Send + 'static,
        T: 'static,
    {
        new_device_cb(TestCase::Fido2Simple, &always_alive);
        Ok(Self {})
    }

    pub fn cancel(&mut self) {}
}
