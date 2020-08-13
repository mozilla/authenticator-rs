/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use runloop::RunLoop;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::vec;
use std::{io, string, thread};

use crate::authenticatorservice::AuthenticatorTransport;
use crate::statecallback::StateCallback;
use crate::virtualdevices::webdriver::testtoken;
use crate::virtualdevices::webdriver::web_api;

pub struct VirtualManager {
    addr: SocketAddr,
    tokens: Arc<Mutex<vec::Vec<testtoken::TestToken>>>,
    rloop: Option<RunLoop>,
}

impl VirtualManager {
    pub fn new() -> io::Result<Self> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let tokens = Arc::new(Mutex::new(vec::Vec::<testtoken::TestToken>::new()));
        let tokclone = tokens.clone();

        let builder = thread::Builder::new().name("WebDriver Command Server".into());
        builder.spawn(move || {
            web_api::serve(tokclone, addr.clone());
        })?;

        Ok(Self {
            addr,
            tokens,
            rloop: None,
        })
    }

    pub fn url(&self) -> string::String {
        format!("http://{}/webauthn/authenticator", &self.addr)
    }
}

impl AuthenticatorTransport for VirtualManager {
    fn register(
        &mut self,
        _flags: crate::RegisterFlags,
        timeout: u64,
        _challenge: Vec<u8>,
        _application: crate::AppId,
        _key_handles: Vec<crate::KeyHandle>,
        _status: Sender<crate::StatusUpdate>,
        callback: StateCallback<Result<crate::RegisterResult, crate::Error>>,
    ) -> Result<(), crate::Error> {
        if self.rloop.is_some() {
            error!("WebDriver state error, prior operation never cancelled.");
            return Err(crate::Error::Unknown);
        }

        let tokens = self.tokens.clone();
        let rloop = try_or!(
            RunLoop::new_with_timeout(
                move |alive| {
                    while alive() {
                        let all_tokens = tokens.lock().unwrap();

                        for token in all_tokens.deref() {
                            if token.is_user_consenting {
                                let register_result = token.register();
                                thread::spawn(move || {
                                    callback.call(register_result);
                                });
                                return;
                            }
                        }
                    }
                },
                timeout
            ),
            |_| Err(crate::Error::Unknown)
        );

        self.rloop = Some(rloop);
        Ok(())
    }

    fn sign(
        &mut self,
        _flags: crate::SignFlags,
        timeout: u64,
        _challenge: Vec<u8>,
        _app_ids: Vec<crate::AppId>,
        _key_handles: Vec<crate::KeyHandle>,
        _status: Sender<crate::StatusUpdate>,
        callback: StateCallback<Result<crate::SignResult, crate::Error>>,
    ) -> Result<(), crate::Error> {
        if self.rloop.is_some() {
            error!("WebDriver state error, prior operation never cancelled.");
            return Err(crate::Error::Unknown);
        }

        let tokens = self.tokens.clone();
        let rloop = try_or!(
            RunLoop::new_with_timeout(
                move |alive| {
                    while alive() {
                        let all_tokens = tokens.lock().unwrap();

                        for token in all_tokens.deref() {
                            if token.is_user_consenting {
                                let sign_result = token.sign();
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
            |_| Err(crate::Error::Unknown)
        );

        self.rloop = Some(rloop);
        Ok(())
    }

    fn cancel(&mut self) -> Result<(), crate::Error> {
        if let Some(r) = self.rloop.take() {
            debug!("WebDriver operation cancelled.");
            r.cancel();
        }
        Ok(())
    }
}
