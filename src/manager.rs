/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io;
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::time::Duration;

use crate::consts::PARAMETER_SIZE;
use crate::statemachine::StateMachine;
use crate::util::StateCallback;
use runloop::RunLoop;

enum QueueAction {
    Register {
        flags: crate::RegisterFlags,
        timeout: u64,
        challenge: Vec<u8>,
        application: crate::AppId,
        key_handles: Vec<crate::KeyHandle>,
        callback: StateCallback<Result<crate::RegisterResult, crate::Error>>,
    },
    Sign {
        flags: crate::SignFlags,
        timeout: u64,
        challenge: Vec<u8>,
        app_ids: Vec<crate::AppId>,
        key_handles: Vec<crate::KeyHandle>,
        callback: StateCallback<Result<crate::SignResult, crate::Error>>,
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
                    Ok(QueueAction::Register {
                        flags,
                        timeout,
                        challenge,
                        application,
                        key_handles,
                        callback,
                    }) => {
                        // This must not block, otherwise we can't cancel.
                        sm.register(
                            flags,
                            timeout,
                            challenge,
                            application,
                            key_handles,
                            callback,
                        );
                    }
                    Ok(QueueAction::Sign {
                        flags,
                        timeout,
                        challenge,
                        app_ids,
                        key_handles,
                        callback,
                    }) => {
                        // This must not block, otherwise we can't cancel.
                        sm.sign(flags, timeout, challenge, app_ids, key_handles, callback);
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

    pub fn register<F>(
        &self,
        flags: crate::RegisterFlags,
        timeout: u64,
        challenge: Vec<u8>,
        application: crate::AppId,
        key_handles: Vec<crate::KeyHandle>,
        callback: F,
    ) -> Result<(), crate::Error>
    where
        F: Fn(Result<crate::RegisterResult, crate::Error>),
        F: Send + 'static,
    {
        if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
            return Err(crate::Error::Unknown);
        }

        for key_handle in &key_handles {
            if key_handle.credential.len() > 256 {
                return Err(crate::Error::Unknown);
            }
        }

        let callback = StateCallback::new(Box::new(callback));
        let action = QueueAction::Register {
            flags,
            timeout,
            challenge,
            application,
            key_handles,
            callback,
        };
        self.tx.send(action).map_err(|_| crate::Error::Unknown)
    }

    pub fn sign<F>(
        &self,
        flags: crate::SignFlags,
        timeout: u64,
        challenge: Vec<u8>,
        app_ids: Vec<crate::AppId>,
        key_handles: Vec<crate::KeyHandle>,
        callback: F,
    ) -> Result<(), crate::Error>
    where
        F: Fn(Result<crate::SignResult, crate::Error>),
        F: Send + 'static,
    {
        if challenge.len() != PARAMETER_SIZE {
            return Err(crate::Error::Unknown);
        }

        if app_ids.is_empty() {
            return Err(crate::Error::Unknown);
        }

        for app_id in &app_ids {
            if app_id.len() != PARAMETER_SIZE {
                return Err(crate::Error::Unknown);
            }
        }

        for key_handle in &key_handles {
            if key_handle.credential.len() > 256 {
                return Err(crate::Error::Unknown);
            }
        }

        let callback = StateCallback::new(Box::new(callback));
        let action = QueueAction::Sign {
            flags,
            timeout,
            challenge,
            app_ids,
            key_handles,
            callback,
        };
        self.tx.send(action).map_err(|_| crate::Error::Unknown)
    }

    pub fn cancel(&self) -> Result<(), crate::Error> {
        self.tx
            .send(QueueAction::Cancel)
            .map_err(|_| crate::Error::Unknown)
    }
}

impl Drop for U2FManager {
    fn drop(&mut self) {
        self.queue.cancel();
    }
}
