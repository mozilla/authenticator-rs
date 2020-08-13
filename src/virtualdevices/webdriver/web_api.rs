/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::{string, vec};
use warp::{http::StatusCode, Filter};

use crate::virtualdevices::webdriver::testtoken;

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
pub async fn serve(tokens: Arc<Mutex<vec::Vec<testtoken::TestToken>>>, addr: SocketAddr) {
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
            let tt = testtoken::TestToken::new(
                *counter,
                protocol,
                auth.is_user_consenting,
                auth.has_user_verification,
                auth.is_user_verified,
                auth.has_resident_key,
            );

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
