/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::{string, vec};
use warp::{
    http::{uri, StatusCode},
    Filter,
};

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

#[derive(Deserialize)]
struct AddCredential {
    #[serde(rename = "credentialId")]
    credential_id: String,
    #[serde(rename = "isResidentCredential")]
    is_resident_credential: bool,
    #[serde(rename = "rpId")]
    rp_id: String,
    #[serde(rename = "privateKey")]
    private_key: String,
    #[serde(rename = "userHandle")]
    #[serde(default)]
    user_handle: String,
    #[serde(rename = "signCount")]
    sign_count: u64,
}

macro_rules! try_or_status_code {
    ($val:expr, $text:expr, $statuscode:expr) => {
        match $val {
            Ok(v) => v,
            Err(e) => {
                return warp::reply::with_status(
                    format!("{} {}: {}", stringify!($text), line!(), e),
                    $statuscode,
                );
            }
        }
    };
}

macro_rules! try_or_internal_error {
    ($val:expr) => {
        try_or_status_code!($val, "internal error", StatusCode::INTERNAL_SERVER_ERROR);
    };
}

macro_rules! try_or_invalid_argument {
    ($val:expr) => {
        try_or_status_code!($val, "invalid argument", StatusCode::BAD_REQUEST);
    };
}

fn validate_rp_id(rp_id: &String) -> Result<(), crate::Error> {
    if let Ok(uri) = rp_id.parse::<uri::Uri>().map_err(|_| crate::Error::Unknown) {
        if uri.scheme().is_none()
            && uri.path_and_query().is_none()
            && uri.port().is_none()
            && uri.host().is_some()
        {
            if uri.authority().unwrap() == uri.host().unwrap() {
                // Don't try too hard to ensure it's a valid domain, just
                // ensure there's a label delim in there somewhere
                if uri.host().unwrap().find(".").is_some() {
                    return Ok(());
                }
            }
        }
    }
    Err(crate::Error::Unknown)
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
                        format!("invalid argument"),
                        StatusCode::BAD_REQUEST,
                    );
                }
            };

            warp::reply::with_status(format!("deleted authenticator id={}", &id), StatusCode::OK)
        });

    let add_credential_tokens = tokens.clone();
    let add_credential = warp::path!("webauthn" / "authenticator" / u64 / "credential")
        .and(warp::body::json())
        .map(move |id: u64, auth: AddCredential| {
            let mut all_tokens = try_or_internal_error!(add_credential_tokens.lock());

            let credential = try_or_invalid_argument!(base64::decode_config(
                &auth.credential_id,
                base64::URL_SAFE
            ));

            let privkey = try_or_invalid_argument!(base64::decode_config(
                &auth.private_key,
                base64::URL_SAFE
            ));

            try_or_invalid_argument!(validate_rp_id(&auth.rp_id));

            if let Ok(idx) = all_tokens.binary_search_by_key(&id, |probe| probe.id) {
                let tt = &all_tokens[idx];

                return warp::reply::with_status(
                    format!("added credential to authenticator id={}", &id),
                    StatusCode::OK,
                );
            }

            warp::reply::with_status(format!("invalid argument"), StatusCode::BAD_REQUEST)
        });

    let routes = creation.or(deletion).or(add_credential);
    warp::serve(routes).run(addr).await;
}

#[cfg(test)]
mod tests {
    use super::validate_rp_id;

    #[test]
    fn test_validate_rp_id() {
        assert_eq!(
            validate_rp_id(&String::from("http://example.com")),
            Err(crate::Error::Unknown)
        );
        assert_eq!(
            validate_rp_id(&String::from("https://example.com")),
            Err(crate::Error::Unknown)
        );
        assert_eq!(
            validate_rp_id(&String::from("example.com:443")),
            Err(crate::Error::Unknown)
        );
        assert_eq!(
            validate_rp_id(&String::from("example.com/path")),
            Err(crate::Error::Unknown)
        );
        assert_eq!(
            validate_rp_id(&String::from("example.com:443/path")),
            Err(crate::Error::Unknown)
        );
        assert_eq!(
            validate_rp_id(&String::from("user:pass@example.com")),
            Err(crate::Error::Unknown)
        );
        assert_eq!(
            validate_rp_id(&String::from("com")),
            Err(crate::Error::Unknown)
        );
        assert_eq!(validate_rp_id(&String::from("example.com")), Ok(()));
    }
}
