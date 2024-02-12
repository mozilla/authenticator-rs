/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Key,
};
use authenticator::{
    authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs},
    crypto::COSEAlgorithm,
    ctap2::{
        commands::large_blobs::LargeBlobArrayElement,
        server::{
            AuthenticationExtensionsClientInputs, AuthenticatorExtensionsCredBlob,
            PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
            PublicKeyCredentialUserEntity, RelyingParty, ResidentKeyRequirement, Transport,
            UserVerificationRequirement,
        },
    },
    statecallback::StateCallback,
    Pin, StatusPinUv, StatusUpdate,
};
use getopts::{Matches, Options};
use sha2::{Digest, Sha256};
use std::sync::mpsc::{channel, RecvError};
use std::{convert::TryInto, io::Write};
use std::{env, io, thread};

fn print_usage(program: &str, opts: Options) {
    println!("------------------------------------------------------------------------");
    println!("This program registers 3x the same origin with different users and");
    println!("requests 'discoverable credentials' for them.");
    println!("After that, we try to log in to that origin and list all credentials found.");
    println!("------------------------------------------------------------------------");
    let brief = format!("Usage: {program} [options]");
    print!("{}", opts.usage(&brief));
}

fn ask_user_choice(choices: &[PublicKeyCredentialUserEntity]) -> Option<usize> {
    for (idx, op) in choices.iter().enumerate() {
        println!("({idx}) \"{}\"", op.name.as_ref().unwrap());
    }
    println!("({}) Cancel", choices.len());

    let mut input = String::new();
    loop {
        input.clear();
        print!("Your choice: ");
        io::stdout()
            .lock()
            .flush()
            .expect("Failed to flush stdout!");
        io::stdin()
            .read_line(&mut input)
            .expect("error: unable to read user input");
        if let Ok(idx) = input.trim().parse::<usize>() {
            if idx < choices.len() {
                // Add a newline in case of success for better separation of in/output
                println!();
                return Some(idx);
            } else if idx == choices.len() {
                println!();
                return None;
            }
            println!("invalid input");
        }
    }
}

fn register_user(
    manager: &mut AuthenticatorService,
    username: &str,
    timeout_ms: u64,
    matches: &Matches,
) {
    println!();
    println!("*********************************************************************");
    println!("Asking a security key to register now with user: {username}");
    println!("*********************************************************************");

    println!("Asking a security key to register now...");
    let challenge_str = format!(
        "{}{}{}{}",
        r#"{"challenge": "1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70","#,
        r#" "version": "U2F_V2", "appId": "http://example.com", "username": ""#,
        username,
        r#""}"#
    );
    let mut challenge = Sha256::new();
    challenge.update(challenge_str.as_bytes());
    let chall_bytes = challenge.finalize().into();

    let has_large_blob = matches.opt_present("large_blob_key");
    let name = username.to_string();
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::InteractiveManagement(..)) => {
                panic!("STATUS: This can't happen when doing non-interactive usage");
            }
            Ok(StatusUpdate::SelectDeviceNotice) => {
                println!("STATUS: Please select a device by touching one of them.");
            }
            Ok(StatusUpdate::PresenceRequired) => {
                println!("STATUS: waiting for user presence");
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
            Ok(StatusUpdate::SelectResultNotice(_, _)) => {
                panic!("Unexpected select result notice")
            }
            Ok(StatusUpdate::LargeBlobData(tx, key)) => {
                if has_large_blob {
                    // Let origData equal the opaque large-blob data.
                    let orig_data = format!("This is the large blob for {name}").into_bytes();
                    // Let origSize be the length, in bytes, of origData.
                    let orig_size = orig_data.len() as u64;
                    // Let plaintext equal origData after compression with DEFLATE [RFC1951].
                    let plaintext = flate3::deflate(&orig_data);
                    // Let nonce be a fresh, random, 12-byte value.
                    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                    // Let ciphertext be the AEAD_AES_256_GCM authenticated encryption of plaintext using key, nonce, and the associated data as specified above.
                    let gcm_key = Key::<Aes256Gcm>::from_slice(&key);
                    let cipher = Aes256Gcm::new(gcm_key);
                    let mut payload = Payload::from(plaintext.as_ref());
                    // Associated data: The value 0x626c6f62 ("blob") || uint64LittleEndian(origSize).
                    let mut aad = b"blob".to_vec();
                    aad.extend_from_slice(&orig_size.to_le_bytes());
                    payload.aad = &aad;
                    let ciphertext = cipher
                        .encrypt(&nonce, payload)
                        .expect("Failed to encrypt plaintext large blob");
                    let elem = LargeBlobArrayElement {
                        ciphertext,
                        nonce: nonce.to_vec().try_into().unwrap(),
                        orig_size,
                    };
                    tx.send(elem).expect("Failed to send large blob element");
                } else {
                    panic!("Unexpected large blob data request");
                }
            }
            Err(RecvError) => {
                println!("STATUS: end");
                return;
            }
        }
    });

    let user = PublicKeyCredentialUserEntity {
        id: username.as_bytes().to_vec(),
        name: Some(username.to_string()),
        display_name: None,
    };
    let origin = "https://example.com".to_string();
    let ctap_args = RegisterArgs {
        client_data_hash: chall_bytes,
        relying_party: RelyingParty {
            id: "example.com".to_string(),
            name: None,
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
        exclude_list: vec![PublicKeyCredentialDescriptor {
            id: vec![],
            transports: vec![Transport::USB, Transport::NFC],
        }],
        user_verification_req: UserVerificationRequirement::Required,
        resident_key_req: ResidentKeyRequirement::Required,
        extensions: AuthenticationExtensionsClientInputs {
            cred_props: Some(true),
            cred_blob: matches.opt_present("cred_blob").then(|| {
                AuthenticatorExtensionsCredBlob::AsBytes("My short credBlob".as_bytes().to_vec())
            }),
            large_blob_key: matches.opt_present("large_blob_key").then_some(true),
            ..Default::default()
        },
        pin: None,
        use_ctap1_fallback: false,
    };

    let attestation_object;
    loop {
        let (register_tx, register_rx) = channel();
        let callback = StateCallback::new(Box::new(move |rv| {
            register_tx.send(rv).unwrap();
        }));

        if let Err(e) = manager.register(timeout_ms, ctap_args, status_tx, callback) {
            panic!("Couldn't register: {:?}", e);
        };

        let register_result = register_rx
            .recv()
            .expect("Problem receiving, unable to continue");
        match register_result {
            Ok(a) => {
                println!("Ok!");
                attestation_object = a;
                break;
            }
            Err(e) => panic!("Registration failed: {:?}", e),
        };
    }

    println!("Register result: {:?}", &attestation_object);

    if matches.opt_present("large_blob_key") {
        println!("Adding large blob key");
    }
}

fn extract_associated_large_blobs(key: Vec<u8>, array: Vec<LargeBlobArrayElement>) -> Vec<String> {
    let valid_elements = array
        .iter()
        .filter_map(|e| {
            let gcm_key = Key::<Aes256Gcm>::from_slice(&key);
            let cipher = Aes256Gcm::new(gcm_key);
            let mut payload = Payload::from(e.ciphertext.as_slice());
            // Associated data: The value 0x626c6f62 ("blob") || uint64LittleEndian(origSize).
            let mut aad = b"blob".to_vec();
            aad.extend_from_slice(&e.orig_size.to_le_bytes());
            payload.aad = &aad;
            let plaintext = cipher.decrypt(e.nonce.as_slice().into(), payload).ok();
            plaintext
        })
        .map(|d| flate3::inflate(&d)) // TODO: Check resulting length and compare to orig_size
        .map(|d| String::from_utf8_lossy(&d).to_string())
        .collect();
    valid_elements
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
    opts.optflag("s", "skip_reg", "Skip registration");
    opts.optflag("b", "cred_blob", "With credBlob");
    opts.optflag("l", "large_blob_key", "With largeBlobKey-extension");
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

    let timeout_ms = match matches.opt_get_default::<u64>("timeout", 15) {
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

    if !matches.opt_present("skip_reg") {
        for username in &["A. User", "A. Nother", "Dr. Who"] {
            register_user(&mut manager, username, timeout_ms, &matches)
        }
    }

    println!();
    println!("*********************************************************************");
    println!("Asking a security key to sign now, with the data from the register...");
    println!("*********************************************************************");

    // Discovering creds:
    let allow_list = Vec::new();
    let origin = "https://example.com".to_string();
    let challenge_str = format!(
        "{}{}",
        r#"{"challenge": "1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70","#,
        r#" "version": "U2F_V2", "appId": "http://example.com" "#,
    );

    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::InteractiveManagement(..)) => {
                panic!("STATUS: This can't happen when doing non-interactive usage");
            }
            Ok(StatusUpdate::SelectDeviceNotice) => {
                println!("STATUS: Please select a device by touching one of them.");
            }
            Ok(StatusUpdate::PresenceRequired) => {
                println!("STATUS: waiting for user presence");
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
            Ok(StatusUpdate::SelectResultNotice(index_sender, users)) => {
                println!("Multiple signatures returned. Select one or cancel.");
                let idx = ask_user_choice(&users);
                index_sender.send(idx).expect("Failed to send choice");
            }
            Ok(StatusUpdate::LargeBlobData(..)) => {
                panic!("Unexpected large blob data request")
            }
            Err(RecvError) => {
                println!("STATUS: end");
                return;
            }
        }
    });

    let mut challenge = Sha256::new();
    challenge.update(challenge_str.as_bytes());
    let chall_bytes = challenge.finalize().into();
    let ctap_args = SignArgs {
        client_data_hash: chall_bytes,
        origin,
        relying_party_id: "example.com".to_string(),
        allow_list,
        user_verification_req: UserVerificationRequirement::Required,
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs {
            cred_blob: matches
                .opt_present("cred_blob")
                .then_some(AuthenticatorExtensionsCredBlob::AsBool(true)),
            large_blob_key: matches.opt_present("large_blob_key").then_some(true),
            ..Default::default()
        },
        pin: None,
        use_ctap1_fallback: false,
    };

    loop {
        let (sign_tx, sign_rx) = channel();

        let callback = StateCallback::new(Box::new(move |rv| {
            sign_tx.send(rv).unwrap();
        }));

        if let Err(e) = manager.sign(timeout_ms, ctap_args, status_tx, callback) {
            panic!("Couldn't sign: {:?}", e);
        }

        let sign_result = sign_rx
            .recv()
            .expect("Problem receiving, unable to continue");

        match sign_result {
            Ok(assertion_object) => {
                println!("Assertion Object: {assertion_object:?}");
                println!("-----------------------------------------------------------------");
                println!("Found credentials:");
                println!(
                    "{:?}",
                    assertion_object
                        .assertion
                        .user
                        .clone()
                        .unwrap()
                        .name
                        .unwrap() // Unwrapping here, as these shouldn't fail
                );
                println!("-----------------------------------------------------------------");
                if matches.opt_present("large_blob_key") {
                    let large_blobs = extract_associated_large_blobs(
                        assertion_object.large_blob_key.unwrap(),
                        assertion_object.large_blob_array.unwrap(),
                    );
                    println!("Associated large blobs: {large_blobs:?}");
                }
                println!("Done.");
                break;
            }
            Err(e) => panic!("Signing failed: {:?}", e),
        }
    }
}
