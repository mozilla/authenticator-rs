/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use pcsc::*;
use runloop::RunLoop;
use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::option::Option;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::apdu::*;
use crate::consts::*;
use crate::errors;
use crate::util::{io_err, trace_hex};

use crate::authenticatorservice::AuthenticatorTransport;
use crate::statecallback::StateCallback;
use crate::statemachine::StateMachine;
use crate::u2ftypes::{U2FDeviceInfo, U2FInfoQueryable};

fn sendrecv(card: &mut Card, send: &[u8]) -> io::Result<Vec<u8>> {
    trace_hex("NFC send", send);
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    match card.transmit(send, &mut rapdu_buf) {
        Ok(rapdu) => {
            trace_hex("NFC recv", rapdu);
            Ok(rapdu.to_vec())
        }
        Err(err) => {
            trace!("NFC error: {}", err);
            let s = format!("{}", err);
            Err(io_err(&s))
        }
    }
}

impl APDUDevice for Card {
    fn init_apdu(&mut self) -> io::Result<()> {
        let out = APDU::serialize_short(U2F_SELECT_FILE, U2F_SELECT_DIRECT, &U2F_AID)?;
        let ret = sendrecv(self, &out)?;
        let (_, status) = APDU::deserialize(ret)?;
        apdu_status_to_result(status, ())
    }

    fn send_apdu(&mut self, cmd: u8, p1: u8, send: &[u8]) -> io::Result<(Vec<u8>, [u8; 2])> {
        // Some devices, such as the Yubikey 4, freak out if an APDU which _would_ fit a short
        // command is sent as an extended command. This means we must use short, even though
        // that means chaining the responses together.
        // The whole response would have fit in an extended reply, but it seems we can't have nice
        // things.
        let mut data: Vec<u8> = Vec::new();

        let out = APDU::serialize_short(cmd, p1, send)?;
        let ret = sendrecv(self, &out)?;
        let (mut more, [s1, s2]) = APDU::deserialize(ret)?;
        data.append(&mut more);

        if s1 != U2F_MORE_DATA {
            return Ok((data, [s1, s2]));
        }

        loop {
            let out = APDU::serialize_short(U2F_GET_RESPONSE, 0x00, &[])?;
            let ret = sendrecv(self, &out)?;
            let (mut more, [s1, s2]) = APDU::deserialize(ret)?;
            data.append(&mut more);
            if s1 != U2F_MORE_DATA {
                return Ok((data, [s1, s2]));
            }
        }
    }
}

impl U2FInfoQueryable for Card {
    fn get_device_info(&self) -> U2FDeviceInfo {
        // TODO: actuall return something sane here!
        let vendor = String::from("Unknown Vendor");
        let product = String::from("Unknown Device");

        U2FDeviceInfo {
            vendor_name: vendor.as_bytes().to_vec(),
            device_name: product.as_bytes().to_vec(),
            version_interface: 0,
            version_major: 0,
            version_minor: 0,
            version_build: 0,
            cap_flags: 0,
        }
    }
}

#[derive(Default)]
pub struct NFCManager {
    run_loop: Option<RunLoop>,
}

impl NFCManager {
    fn run<E, F>(&mut self, timeout: u64, fatal_error: E, f: F) -> crate::Result<()>
    where
        E: Fn() + Sync + Send + 'static,
        F: Fn(&mut Card, &dyn Fn() -> bool) + Sync + Send + Clone + 'static,
    {
        if self.run_loop.is_some() {
            return Err(errors::AuthenticatorError::InternalError(String::from(
                "nfc run loop is already in use",
            )));
        }

        let ctx =
            Context::establish(Scope::User).map_err(|_| errors::AuthenticatorError::Platform)?;

        let rl = RunLoop::new_with_timeout(
            move |alive| {
                let mut child_loops: HashMap<CString, RunLoop> = HashMap::new();

                let mut readers_buf = [0; 2048];
                // We _could_ insert `ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE)`
                // to be reminded of reader insertion/removal,
                // but this is not guaranteed to be supported
                // and we need to poll anyways.
                let mut reader_states: Vec<ReaderState> = Vec::new();

                while alive() {
                    // Add new readers.
                    let names = match ctx.list_readers(&mut readers_buf) {
                        Ok(n) => n,
                        Err(_) => {
                            fatal_error();
                            break;
                        }
                    };
                    for name in names {
                        if !reader_states.iter().any(|reader| reader.name() == name) {
                            debug!("Adding reader {:?}", name);
                            reader_states.push(ReaderState::new(name, State::UNAWARE));
                        }
                    }

                    // Remove dead readers.
                    fn is_dead(reader: &ReaderState) -> bool {
                        reader
                            .event_state()
                            .intersects(State::UNKNOWN | State::IGNORE)
                    }
                    for reader in &reader_states {
                        if is_dead(reader) {
                            debug!("Removing reader {:?}", reader.name());
                        }
                    }
                    reader_states.retain(|reader| !is_dead(reader));

                    // Let backend know that we know about the reader state.
                    // Otherwise it will keep trying to update us.
                    for rs in &mut reader_states {
                        rs.sync_current_state();
                    }

                    if reader_states.is_empty() {
                        // No readers available. This means that `get_status_change` will return
                        // immediately without any work, causing a busy-loop.
                        // Let's wait for a bit and look for a new reader.
                        thread::sleep(Duration::from_millis(500));
                        continue;
                    }

                    // This call is blocking, so we must give it _some_ timeout in order for
                    // the `alive()` check to work.
                    let timeout = Duration::from_millis(100);
                    if let Err(e) = ctx.get_status_change(timeout, &mut reader_states) {
                        if e == Error::Timeout {
                            continue;
                        }
                        fatal_error();
                        break;
                    }

                    for reader in &mut reader_states {
                        let state = reader.event_state();
                        let name = CString::from(reader.name());

                        trace!("Reader {:?}: state {:?}", name, state);

                        // TODO: this will keep spamming yubikeys with usb auth attempts???
                        // probably not harmful, but is there a way to avoid it?
                        if state.contains(State::PRESENT) && !state.contains(State::EXCLUSIVE) {
                            let mut card =
                                match ctx.connect(&name, ShareMode::Shared, Protocols::ANY) {
                                    Ok(card) => card,
                                    _ => continue,
                                };

                            let my_f = f.clone();
                            let cl = RunLoop::new(move |alive| {
                                if alive() {
                                    my_f(&mut card, alive);
                                }
                            });

                            if let Ok(x) = cl {
                                child_loops.insert(name, x);
                            }
                        } else if let Some(cl) = child_loops.remove(&name) {
                            cl.cancel();
                        }
                    }
                }

                for (_, child) in child_loops {
                    child.cancel();
                }
            },
            timeout,
        )
        .map_err(|_| errors::AuthenticatorError::Platform)?;
        self.run_loop = Some(rl);
        Ok(())
    }

    pub fn new() -> Self {
        Self { run_loop: None }
    }

    fn stop(&mut self) {
        if let Some(rl) = &self.run_loop {
            rl.cancel();
            self.run_loop = None;
        }
    }
}

impl Drop for NFCManager {
    fn drop(&mut self) {
        self.stop();
    }
}

impl AuthenticatorTransport for NFCManager {
    fn register(
        &mut self,
        flags: crate::RegisterFlags,
        timeout: u64,
        challenge: Vec<u8>,
        application: crate::AppId,
        key_handles: Vec<crate::KeyHandle>,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::RegisterResult>>,
    ) -> crate::Result<()> {
        let status_mutex = Arc::new(Mutex::new(status));
        let cbc = callback.clone();
        let err = move || cbc.call(Err(errors::AuthenticatorError::Platform));
        self.run(timeout, err, move |card, alive| {
            StateMachine::register(
                card,
                flags,
                &challenge,
                application.clone(),
                &key_handles,
                &status_mutex,
                &callback,
                alive,
            );
        })
    }

    fn sign(
        &mut self,
        flags: crate::SignFlags,
        timeout: u64,
        challenge: Vec<u8>,
        app_ids: Vec<crate::AppId>,
        key_handles: Vec<crate::KeyHandle>,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<crate::Result<crate::SignResult>>,
    ) -> crate::Result<()> {
        let status_mutex = Arc::new(Mutex::new(status));
        let cbc = callback.clone();
        let err = move || cbc.call(Err(errors::AuthenticatorError::Platform));
        self.run(timeout, err, move |card, alive| {
            StateMachine::sign(
                card,
                flags,
                &challenge,
                &app_ids,
                &key_handles,
                &status_mutex,
                &callback,
                alive,
            );
        })
    }

    fn cancel(&mut self) -> crate::Result<()> {
        self.stop();
        Ok(())
    }
}
