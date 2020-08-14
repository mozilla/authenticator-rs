/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use serde::{Deserialize, Serialize};
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

#[derive(Serialize, Deserialize, Clone)]
struct AddVirtualAuthenticator {
    protocol: string::String,
    transport: string::String,
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

#[derive(Serialize, Deserialize, Clone)]
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
                    format!("{} line {}, err: {}", $text, line!(), e),
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

fn authenticator_add(
    authenticator_counter: Arc<Mutex<u64>>,
    tokens: Arc<Mutex<vec::Vec<testtoken::TestToken>>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("webauthn" / "authenticator")
        .and(warp::post())
        .and(warp::body::json())
        .map(move |auth: AddVirtualAuthenticator| {
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

            let mut counter = try_or_internal_error!(authenticator_counter.lock());
            *counter += 1;

            let tt = testtoken::TestToken::new(
                *counter,
                protocol,
                auth.is_user_consenting,
                auth.has_user_verification,
                auth.is_user_verified,
                auth.has_resident_key,
            );

            let mut all_tokens = try_or_internal_error!(tokens.lock());
            all_tokens.push(tt);

            warp::reply::with_status(format!("{}", &counter), StatusCode::OK)
        })
}

fn authenticator_delete(
    tokens: Arc<Mutex<vec::Vec<testtoken::TestToken>>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("webauthn" / "authenticator" / u64)
        .and(warp::delete())
        .map(move |id: u64| {
            let mut all_tokens = try_or_internal_error!(tokens.lock());
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
        })
}

fn authenticator_credential_add(
    tokens: Arc<Mutex<vec::Vec<testtoken::TestToken>>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("webauthn" / "authenticator" / u64 / "credential")
        .and(warp::body::json())
        .map(move |id: u64, auth: AddCredential| {
            let credential = try_or_invalid_argument!(base64::decode_config(
                &auth.credential_id,
                base64::URL_SAFE
            ));

            let privkey = try_or_invalid_argument!(base64::decode_config(
                &auth.private_key,
                base64::URL_SAFE
            ));

            let userhandle = try_or_invalid_argument!(base64::decode_config(
                &auth.user_handle,
                base64::URL_SAFE
            ));

            try_or_invalid_argument!(validate_rp_id(&auth.rp_id));

            let mut all_tokens = try_or_internal_error!(tokens.lock());
            if let Ok(idx) = all_tokens.binary_search_by_key(&id, |probe| probe.id) {
                let tt = &mut all_tokens[idx];

                tt.insert_credential(
                    &credential,
                    &privkey,
                    auth.rp_id,
                    auth.is_resident_credential,
                    &userhandle,
                    auth.sign_count,
                );

                return warp::reply::with_status(
                    format!("added credential to authenticator id={}", &id),
                    StatusCode::OK,
                );
            }

            warp::reply::with_status(format!("invalid argument"), StatusCode::BAD_REQUEST)
        })
}

#[tokio::main]
pub async fn serve(tokens: Arc<Mutex<vec::Vec<testtoken::TestToken>>>, addr: SocketAddr) {
    let authenticator_counter = Arc::new(Mutex::new(0));

    let auth_creation = authenticator_add(authenticator_counter, tokens.clone());
    let auth_deletion = authenticator_delete(tokens.clone());
    let add_credential = authenticator_credential_add(tokens.clone());

    let routes = auth_creation.or(auth_deletion).or(add_credential);

    warp::serve(routes).run(addr).await;
}

#[cfg(test)]
mod tests {
    use super::{testtoken::*, *};
    use std::sync::{Arc, Mutex};

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

    fn mk_token_list(ids: &[u64]) -> Arc<Mutex<Vec<TestToken>>> {
        let mut list = Vec::new();
        for id in ids {
            list.push(TestToken::new(
                *id,
                TestWireProtocol::CTAP1,
                true,
                true,
                true,
                true,
            ));
        }
        Arc::new(Mutex::new(list))
    }

    #[tokio::test]
    async fn test_authenticator_add() {
        let filter = authenticator_add(Arc::new(Mutex::new(0)), mk_token_list(&[]));

        {
            let res = warp::test::request()
                .method("POST")
                .path("/webauthn/authenticator")
                .reply(&filter)
                .await;
            assert_eq!(res.status(), 400);
        }

        let valid_add = AddVirtualAuthenticator {
            protocol: "ctap1/u2f".to_string(),
            transport: "usb".to_string(),
            has_resident_key: false,
            has_user_verification: false,
            is_user_consenting: false,
            is_user_verified: false,
        };

        {
            let mut invalid = valid_add.clone();
            invalid.protocol = "unknown".to_string();
            let res = warp::test::request()
                .method("POST")
                .path("/webauthn/authenticator")
                .json(&invalid)
                .reply(&filter)
                .await;
            assert_eq!(res.status(), 400);
            assert_eq!(res.body(), "unknown protocol: unknown");
        }

        {
            let mut unknown = valid_add.clone();
            unknown.transport = "unknown".to_string();
            let res = warp::test::request()
                .method("POST")
                .path("/webauthn/authenticator")
                .json(&unknown)
                .reply(&filter)
                .await;
            assert_eq!(res.status(), 200);
            assert_eq!(res.body(), "1");
        }

        {
            let res = warp::test::request()
                .method("POST")
                .path("/webauthn/authenticator")
                .json(&valid_add)
                .reply(&filter)
                .await;
            assert_eq!(res.status(), 200);
            assert_eq!(res.body(), "2");
        }
    }

    #[tokio::test]
    async fn test_authenticator_delete() {
        let filter = authenticator_delete(mk_token_list(&[32]));

        {
            let res = warp::test::request()
                .method("DELETE")
                .path("/webauthn/authenticator/3")
                .reply(&filter)
                .await;
            assert_eq!(res.status(), 400);
            assert_eq!(res.body(), "invalid argument");
        }

        {
            let res = warp::test::request()
                .method("DELETE")
                .path("/webauthn/authenticator/32")
                .reply(&filter)
                .await;
            assert_eq!(res.status(), 200);
            assert_eq!(res.body(), "deleted authenticator id=32");
        }

        {
            let res = warp::test::request()
                .method("DELETE")
                .path("/webauthn/authenticator/42")
                .reply(&filter)
                .await;
            assert_eq!(res.status(), 400);
            assert_eq!(res.body(), "invalid argument");
        }
    }

    #[tokio::test]
    async fn test_authenticator_credential_add() {
        let list = mk_token_list(&[1]);
        let filter = authenticator_credential_add(list.clone());

        let valid_add_credential = AddCredential {
            credential_id: base64::encode_config(b"hello internet~", base64::URL_SAFE),
            is_resident_credential: true,
            rp_id: "valid.rpid".to_string(),
            private_key: base64::encode_config(b"hello internet~", base64::URL_SAFE),
            user_handle: base64::encode_config(b"hello internet~", base64::URL_SAFE),
            sign_count: 0,
        };

        {
            let res = warp::test::request()
                .method("POST")
                .path("/webauthn/authenticator/1/credential")
                .reply(&filter)
                .await;
            assert_eq!(res.status(), 400);
        }

        {
            let mut invalid = valid_add_credential.clone();
            invalid.credential_id = "!@#$ invalid base64".to_string();
            let res = warp::test::request()
                .method("POST")
                .path("/webauthn/authenticator/1/credential")
                .json(&invalid)
                .reply(&filter)
                .await;
            assert_eq!(res.status(), 400);
            assert_eq!(res.body().slice(0..16), "invalid argument");
        }

        {
            let mut invalid = valid_add_credential.clone();
            invalid.rp_id = "example".to_string();
            let res = warp::test::request()
                .method("POST")
                .path("/webauthn/authenticator/1/credential")
                .json(&invalid)
                .reply(&filter)
                .await;
            assert_eq!(res.status(), 400);
            assert_eq!(res.body().slice(0..16), "invalid argument");
        }

        {
            let mut invalid = valid_add_credential.clone();
            invalid.rp_id = "https://example.com".to_string();
            let res = warp::test::request()
                .method("POST")
                .path("/webauthn/authenticator/1/credential")
                .json(&invalid)
                .reply(&filter)
                .await;
            assert_eq!(res.status(), 400);
            assert_eq!(res.body().slice(0..16), "invalid argument");
        }

        {
            let mut no_user_handle = valid_add_credential.clone();
            no_user_handle.user_handle = "".to_string();
            let res = warp::test::request()
                .method("POST")
                .path("/webauthn/authenticator/1/credential")
                .json(&no_user_handle)
                .reply(&filter)
                .await;
            assert_eq!(res.status(), 200);
            assert_eq!(res.body(), "added credential to authenticator id=1");
            let locked_list = list.lock().unwrap();
            assert_eq!(1, locked_list[0].credentials.len());
            let c = &locked_list[0].credentials[0];
            assert!(c.user_handle.is_empty());
        }

        {
            let res = warp::test::request()
                .method("POST")
                .path("/webauthn/authenticator/1/credential")
                .json(&valid_add_credential)
                .reply(&filter)
                .await;
            assert_eq!(res.status(), 200);
            assert_eq!(res.body(), "added credential to authenticator id=1");
            let locked_list = list.lock().unwrap();
            assert_eq!(2, locked_list[0].credentials.len());
            let c = &locked_list[0].credentials[1];
            assert!(!c.user_handle.is_empty());
        }
    }
}
