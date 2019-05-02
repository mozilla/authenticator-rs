/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate authenticator;
extern crate env_logger;
extern crate log;

use std::sync::mpsc::channel;

use authenticator::ctap2::commands::Pin;
use authenticator::ctap2::server::{Alg, PublicKeyCredentialParameters, User};
use authenticator::Manager;

macro_rules! try_or {
    ($val:expr, $or:expr) => {
        match $val {
            Ok(v) => v,
            Err(e) => {
                return $or(e);
            }
        }
    };
}

fn main() {
    env_logger::init();

    let manager = Manager::new().unwrap();
    let (tx, rx) = channel();

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

    let register_data = try_or!(rx.recv(), |_| {
        panic!("Problem receiving, unable to continue");
    });
    println!("Register result: {:?}", register_data);

    //let (tx, rx) = channel();
    //manager
    //    .sign(
    //        String::from("example.com"),
    //        String::from("https://www.example.com"),
    //        15_000,
    //        vec![0, 1, 2, 3],
    //        User {
    //            id: vec![0],
    //            name: String::from("j.doe"),
    //            display_name: None,
    //            icon: None,
    //        },
    //        vec![PublicKeyCredentialParameters { alg: Alg::ES256 }],
    //        Some(Pin::new("1234")),
    //        move |rv| {
    //            tx.send(rv.unwrap()).unwrap();
    //        },
    //    )
    //    .unwrap();

    //let authenticator_data = try_or!(rx.recv(), |_| {
    //    panic!("Problem receiving, unable to continue");
    //});
    //println!("Register result: {:?}", register_data);
}
