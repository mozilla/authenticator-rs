/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use runloop::RunLoop;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::vec;
use std::{io, string, thread};
use warp::{http::StatusCode, Filter};

use crate::authenticatorservice::AuthenticatorTransport;
use crate::util::StateCallback;

mod testtoken;

fn default_as_false() -> bool {
    false
}
fn default_as_true() -> bool {
    false
}
#[derive(Deserialize)]
struct AddVirtualAuthenticator {
    protocol: string::String,
    // transport: string::String,
    #[serde(rename = "hasResidentKey")]
    #[serde(default = "default_as_false")]
    has_resident_key: bool,
    #[serde(rename = "hasUserVerification")]
    #[serde(default = "default_as_false")]
    has_user_verification: bool,
    #[serde(rename = "isUserConsenting")]
    #[serde(default = "default_as_true")]
    is_user_consenting: bool,
    #[serde(rename = "isUserVerified")]
    #[serde(default = "default_as_false")]
    is_user_verified: bool,
}

#[derive(Debug)]
struct WebDriverError;

impl warp::reject::Reject for WebDriverError {}

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
            serve(tokclone, addr.clone());
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

macro_rules! try_or_internal_error {
    ($val:expr) => {
        match $val {
            Ok(v) => v,
            Err(e) => {
                return warp::reply::with_status(
                    format!("internal error on line {}: {}", line!(), e),
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        }
    };
}

#[tokio::main]
async fn serve(tokens: Arc<Mutex<vec::Vec<testtoken::TestToken>>>, addr: SocketAddr) {
    let authenticator_counter = Arc::new(Mutex::new(0));

    let creation_tokens = tokens.clone();
    let creation = warp::path!("webauthn" / "authenticator")
        .and(warp::post())
        .and(warp::body::json())
        .map(move |auth: AddVirtualAuthenticator| {
            let mut counter = try_or_internal_error!(authenticator_counter.lock());
            *counter += 1;
            let protocol = match auth.protocol.as_str() {
                "ctap1/u2f" => testtoken::TestWireProtocol::CTAP1,
                "ctap2" => testtoken::TestWireProtocol::CTAP2,
                _ => {
                    return warp::reply::with_status(
                        format!("unknown protocol: {}", auth.protocol),
                        StatusCode::BAD_REQUEST,
                    )
                }
            };
            let tt = testtoken::TestToken {
                id: *counter,
                protocol,
                is_user_consenting: auth.is_user_consenting,
                has_user_verification: auth.has_user_verification,
                is_user_verified: auth.is_user_verified,
                has_resident_key: auth.has_resident_key,
            };

            let mut all_tokens = try_or_internal_error!(creation_tokens.lock());
            all_tokens.push(tt);

            warp::reply::with_status(format!("{}", &counter), StatusCode::OK)
        });

    let deletion_tokens = tokens.clone();
    let deletion = warp::path!("webauthn" / "authenticator" / u64)
        .and(warp::delete())
        .map(move |id: u64| {
            let mut all_tokens = try_or_internal_error!(deletion_tokens.lock());
            match all_tokens.binary_search_by_key(&id, |probe| probe.id) {
                Ok(idx) => all_tokens.remove(idx),
                Err(_) => {
                    return warp::reply::with_status(
                        format!("authenticator id={} not found", id),
                        StatusCode::NOT_FOUND,
                    );
                }
            };

            warp::reply::with_status(format!("deleted authenticator id={}", &id), StatusCode::OK)
        });

    let routes = creation.or(deletion);

    warp::serve(routes).run(addr).await;
}
