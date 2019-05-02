/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use runloop::RunLoop;
use std::path::PathBuf;
use transport::platform::monitor::Monitor;
use util::ErrorCallback;

pub struct Transaction {
    // Handle to the thread loop.
    thread: Option<RunLoop>,
}

impl Transaction {
    pub fn new<F, EC>(timeout: u64, callback: EC, new_device_cb: F) -> Result<Self, ::Error>
    where
        EC: ErrorCallback + Send + 'static,
        F: Fn(PathBuf, &Fn() -> bool) + Sync + Send + 'static,
    {
        let thread = RunLoop::new_with_timeout(
            move |alive| {
                // Create a new device monitor.
                let mut monitor = Monitor::new(new_device_cb);

                // Start polling for new devices.
                try_or!(monitor.run(alive), |_| callback.errcall(::Error::Unknown));

                // Send an error, if the callback wasn't called already.
                callback.errcall(::Error::NotAllowed);
            },
            timeout,
        )
        .map_err(|_| ::Error::Unknown)?;

        Ok(Self {
            thread: Some(thread),
        })
    }

    pub fn cancel(&mut self) {
        // This must never be None.
        self.thread.take().unwrap().cancel();
    }
}
