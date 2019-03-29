/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::sync::mpsc;

use crate::ctap2::commands::Pin;
use crate::ctap2::server::{Alg, PublicKeyCredentialParameters, User};
use crate::transport::platform::TestCase;
use crate::FidoManager;

mod common;

#[test]
fn test_write_error() {
    common::setup();
    debug!("activating writeerror");
    TestCase::activate(TestCase::WriteError);

    let manager = FidoManager::new().unwrap();
    let (tx, rx) = mpsc::channel();

    manager
        .register(
            String::from("example.com"),
            String::from("https://www.example.com"),
            15_000,
            vec![0, 1, 2, 3],
            User {
                id: vec![0],
                name: String::from("j.doe"),
                display_name: None,
                icon: None,
            },
            vec![PublicKeyCredentialParameters { alg: Alg::ES256 }],
            Some(Pin::new("1234")),
            move |rv| {
                tx.send(rv.unwrap()).unwrap();
            },
        )
        .unwrap();

    let res = rx.recv();
    debug!("res = {:?}", res);
    assert_eq!(res, Err(mpsc::RecvError));
}

#[test]
fn test_simple_fido2() {
    common::setup();
    TestCase::activate(TestCase::Fido2Simple);

    let manager = FidoManager::new().unwrap();
    let (tx, rx) = mpsc::channel();

    manager
        .register(
            String::from("example.com"),
            String::from("https://www.example.com"),
            15_000,
            vec![0, 1, 2, 3],
            User {
                id: vec![0],
                name: String::from("j.doe"),
                display_name: None,
                icon: None,
            },
            vec![PublicKeyCredentialParameters { alg: Alg::ES256 }],
            Some(Pin::new("1234")),
            move |rv| {
                tx.send(rv.unwrap()).unwrap();
            },
        )
        .unwrap();

    let register_data = try_or!(rx.recv(), |res| {
        debug!("result {:?}", res);
        panic!("Problem receiving, unable to continue");
    });
    println!("Register result: {:?}", register_data);
}
