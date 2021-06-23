/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use authenticator::{
    authenticatorservice::{AuthenticatorService, CtapVersion, RegisterArgsCtap2, SignArgsCtap2},
    ctap2::server::{
        Alg, PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, RelyingParty, Transport,
        User,
    },
    statecallback::StateCallback,
    RegisterResult, SignFlags, SignResult, StatusUpdate,
};
use getopts::Options;
use sha2::{Digest, Sha256};
use std::sync::mpsc::{channel, RecvError};
use std::{env, thread};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("x", "no-u2f-usb-hid", "do not enable u2f-usb-hid platforms");
    opts.optflag("h", "help", "print this help menu").optopt(
        "t",
        "timeout",
        "timeout in seconds",
        "SEC",
    );

    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!("{}", f.to_string()),
    };
    if matches.opt_present("help") {
        print_usage(&program, opts);
        return;
    }

    let mut manager = AuthenticatorService::new(CtapVersion::CTAP2)
        .expect("The auth service should initialize safely");

    if !matches.opt_present("no-u2f-usb-hid") {
        manager.add_u2f_usb_hid_platform_transports();
    }

    let timeout_ms = match matches.opt_get_default::<u64>("timeout", 15) {
        Ok(timeout_s) => {
            println!("Using {}s as the timeout", &timeout_s);
            timeout_s * 1_000
        }
        Err(e) => {
            println!("{}", e);
            print_usage(&program, opts);
            return;
        }
    };

    println!("Asking a security key to register now...");
    let challenge_str = format!(
        "{}{}",
        r#"{"challenge": "1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70","#,
        r#" "version": "U2F_V2", "appId": "http://example.com"}"#
    );
    let mut challenge = Sha256::default();
    challenge.input(challenge_str.as_bytes());
    let chall_bytes = challenge.result().to_vec();

    // TODO(MS): Needs to be added to RegisterArgsCtap2
    // let flags = RegisterFlags::empty();

    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::DeviceAvailable { dev_info }) => {
                println!("STATUS: device available: {}", dev_info)
            }
            Ok(StatusUpdate::DeviceUnavailable { dev_info }) => {
                println!("STATUS: device unavailable: {}", dev_info)
            }
            Ok(StatusUpdate::Success { dev_info }) => {
                println!("STATUS: success using device: {}", dev_info);
            }
            Err(RecvError) => {
                println!("STATUS: end");
                return;
            }
        }
    });

    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        register_tx.send(rv).unwrap();
    }));

    let user = User {
        id: "user_id".as_bytes().to_vec(),
        icon: None,
        name: "A. User".to_string(),
        display_name: None,
    };
    let origin = "https://example.com".to_string();
    let ctap_args = RegisterArgsCtap2 {
        challenge: chall_bytes.clone(),
        relying_party: RelyingParty {
            id: "example.com".to_string(),
            name: None,
            icon: None,
        },
        origin: origin.clone(),
        user: user.clone(),
        pub_cred_params: vec![
            PublicKeyCredentialParameters { alg: Alg::ES256 },
            PublicKeyCredentialParameters { alg: Alg::RS256 },
        ],
        pin: None,
        exclude_list: vec![PublicKeyCredentialDescriptor {
            id: vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
            transports: vec![Transport::USB, Transport::NFC],
        }],
    };
    manager
        .register(timeout_ms, ctap_args.into(), status_tx.clone(), callback)
        .expect("Couldn't register");

    let register_result = register_rx
        .recv()
        .expect("Problem receiving, unable to continue");
    let (attestation_object, client_data) = match register_result {
        Ok(RegisterResult::CTAP1(_, _)) => panic!("Requested CTAP2, but got CTAP1 results!"),
        Ok(RegisterResult::CTAP2(a, c)) => (a, c),
        Err(e) => panic!("Registration failed: {:?}", e),
    };

    println!("Register result: {:?}", &attestation_object);
    println!("Collected client data: {:?}", &client_data);

    println!("");
    println!("*********************************************************************");
    println!("Asking a security key to sign now, with the data from the register...");
    println!("*********************************************************************");

    let (sign_tx, sign_rx) = channel();

    let callback = StateCallback::new(Box::new(move |rv| {
        sign_tx.send(rv).unwrap();
    }));

    let allow_list;
    if let Some(cred_data) = attestation_object.auth_data.credential_data {
        println!("======================================================= GOT CRED ID");
        allow_list = vec![PublicKeyCredentialDescriptor {
            id: cred_data.credential_id.clone(),
            transports: vec![Transport::USB],
        }];
    } else {
        allow_list = Vec::new();
    }

    let ctap_args = SignArgsCtap2 {
        flags: SignFlags::empty(),
        challenge: chall_bytes,
        origin,
        user,
        relying_party_id: "example.com".to_string(),
        allow_list,
    };

    if let Err(e) = manager.sign(timeout_ms, ctap_args.into(), status_tx, callback) {
        panic!("Couldn't register: {:?}", e);
    }

    let sign_result = sign_rx
        .recv()
        .expect("Problem receiving, unable to continue");
    if let SignResult::CTAP2(assertion_object) = sign_result.expect("Sign failed") {
        println!("Assertion Object: {:?}", assertion_object);
        println!("Done.");
    } else {
        panic!("Expected sign result to be CTAP2, but got CTAP1");
    }
}
