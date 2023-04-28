/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use authenticator::{
    authenticatorservice::{AuthenticatorService, RegisterArgs},
    ctap2::commands::StatusCode,
    ctap2::server::{
        PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, RelyingParty,
        ResidentKeyRequirement, Transport, User, UserVerificationRequirement,
    },
    errors::{AuthenticatorError, CommandError, HIDError},
    statecallback::StateCallback,
    COSEAlgorithm, Pin, RegisterResult, StatusPinUv, StatusUpdate,
};

use getopts::Options;
use sha2::{Digest, Sha256};
use std::sync::mpsc::{channel, RecvError};
use std::{env, thread};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {program} [options]");
    print!("{}", opts.usage(&brief));
}

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
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

    let mut manager =
        AuthenticatorService::new().expect("The auth service should initialize safely");

    manager.add_u2f_usb_hid_platform_transports();

    let timeout_ms = match matches.opt_get_default::<u64>("timeout", 25) {
        Ok(timeout_s) => {
            println!("Using {}s as the timeout", &timeout_s);
            timeout_s * 1_000
        }
        Err(e) => {
            println!("{e}");
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
    let mut challenge = Sha256::new();
    challenge.update(challenge_str.as_bytes());
    let chall_bytes = challenge.finalize().into();

    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::InteractiveManagement(..)) => {
                panic!("STATUS: This can't happen when doing non-interactive usage");
            }
            Ok(StatusUpdate::DeviceAvailable { dev_info }) => {
                println!("STATUS: device available: {dev_info}")
            }
            Ok(StatusUpdate::DeviceUnavailable { dev_info }) => {
                println!("STATUS: device unavailable: {dev_info}")
            }
            Ok(StatusUpdate::Success { dev_info }) => {
                println!("STATUS: success using device: {dev_info}");
            }
            Ok(StatusUpdate::SelectDeviceNotice) => {
                println!("STATUS: Please select a device by touching one of them.");
            }
            Ok(StatusUpdate::DeviceSelected(dev_info)) => {
                println!("STATUS: Continuing with device: {dev_info}");
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender))) => {
                let raw_pin =
                    rpassword::prompt_password_stderr("Enter PIN: ").expect("Failed to read PIN");
                sender.send(Pin::new(&raw_pin)).expect("Failed to send PIN");
                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts))) => {
                println!(
                    "Wrong PIN! {}",
                    attempts.map_or("Try again.".to_string(), |a| format!(
                        "You have {a} attempts left."
                    ))
                );
                let raw_pin =
                    rpassword::prompt_password_stderr("Enter PIN: ").expect("Failed to read PIN");
                sender.send(Pin::new(&raw_pin)).expect("Failed to send PIN");
                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked)) => {
                panic!("Too many failed attempts in one row. Your device has been temporarily blocked. Please unplug it and plug in again.")
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinBlocked)) => {
                panic!("Too many failed attempts. Your device has been blocked. Reset it.")
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidUv(attempts))) => {
                println!(
                    "Wrong UV! {}",
                    attempts.map_or("Try again.".to_string(), |a| format!(
                        "You have {a} attempts left."
                    ))
                );
                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::UvBlocked)) => {
                println!("Too many failed UV-attempts.");
                continue;
            }
            Ok(StatusUpdate::PinUvError(e)) => {
                panic!("Unexpected error: {:?}", e)
            }
            Err(RecvError) => {
                println!("STATUS: end");
                return;
            }
        }
    });

    let user = User {
        id: "user_id".as_bytes().to_vec(),
        icon: None,
        name: Some("A. User".to_string()),
        display_name: None,
    };
    let origin = "https://example.com".to_string();
    let mut ctap_args = RegisterArgs {
        client_data_hash: chall_bytes,
        relying_party: RelyingParty {
            id: "example.com".to_string(),
            name: None,
            icon: None,
        },
        origin,
        user,
        pub_cred_params: vec![
            PublicKeyCredentialParameters {
                alg: COSEAlgorithm::ES256,
            },
            PublicKeyCredentialParameters {
                alg: COSEAlgorithm::RS256,
            },
        ],
        exclude_list: vec![],
        user_verification_req: UserVerificationRequirement::Preferred,
        resident_key_req: ResidentKeyRequirement::Discouraged,
        extensions: Default::default(),
        pin: None,
        use_ctap1_fallback: false,
    };

    loop {
        let (register_tx, register_rx) = channel();
        let callback = StateCallback::new(Box::new(move |rv| {
            register_tx.send(rv).unwrap();
        }));

        if let Err(e) = manager.register(timeout_ms, ctap_args.clone(), status_tx.clone(), callback)
        {
            panic!("Couldn't register: {:?}", e);
        };

        let register_result = register_rx
            .recv()
            .expect("Problem receiving, unable to continue");
        match register_result {
            Ok(RegisterResult::CTAP1(_, _)) => panic!("Requested CTAP2, but got CTAP1 results!"),
            Ok(RegisterResult::CTAP2(a)) => {
                println!("Ok!");
                println!("Registering again with the key_handle we just got back. This should result in a 'already registered' error.");
                let registered_key_handle =
                    a.auth_data.credential_data.unwrap().credential_id.clone();
                ctap_args.exclude_list = vec![PublicKeyCredentialDescriptor {
                    id: registered_key_handle.clone(),
                    transports: vec![Transport::USB],
                }];
                continue;
            }
            Err(AuthenticatorError::HIDError(HIDError::Command(CommandError::StatusCode(
                StatusCode::CredentialExcluded,
                None,
            )))) => {
                println!("Got an 'already registered' error. Quitting.");
                break;
            }
            Err(e) => panic!("Registration failed: {:?}", e),
        };
    }
    println!("Done")
}
