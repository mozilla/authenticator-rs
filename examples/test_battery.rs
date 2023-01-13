/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use authenticator::{
    authenticatorservice::{
        AuthenticatorService, CtapVersion, GetAssertionOptions, MakeCredentialsOptions,
        RegisterArgsCtap2, SignArgsCtap2,
    },
    ctap2::attestation::AuthenticatorDataFlags,
    ctap2::commands::StatusCode,
    ctap2::server::{
        PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, RelyingParty, Transport, User,
    },
    errors::{AuthenticatorError, CommandError, HIDError, PinError},
    statecallback::StateCallback,
    AttestationObject, COSEAlgorithm, Pin, RegisterResult, SignResult, StatusUpdate,
};
use getopts::{Matches, Options};
use log::debug;
use rand::{self, Rng};
use std::sync::mpsc::{channel, RecvError, Sender};
use std::{env, thread};

macro_rules! extract {
    ($source:expr, $matchpattern:pat, $returnval:expr) => {
        match $source {
            $matchpattern => $returnval,
            _ => {
                panic!(
                    "Could not extract expected pattern. Expected {:?}, got {:?}",
                    stringify!($matchpattern),
                    $source
                );
            }
        }
    };
}

const PIN: &str = "1234";

fn print_usage(program: &str, opts: Options) {
    println!("------------------------------------------------------------------------");
    println!("This program runs a variety of tests on the token.");
    println!("ATTENTION: This involves  R E S E T T I N G  your token!");
    println!("------------------------------------------------------------------------");
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    env_logger::init();

    let (_program, _opts, matches) = parse_command_line_options();
    let tests_str = matches.opt_str("tests").unwrap_or_default();
    let tests: Vec<_> = if tests_str.is_empty() {
        Vec::new()
    } else {
        tests_str.split(',').collect()
    };

    println!("------------------------------------------------------------------------");
    println!("This program runs a variety of tests on the token.");
    println!("ATTENTION: This involves  R E S E T T I N G  your token!");
    println!("------------------------------------------------------------------------");

    // CTAP1 tests
    // TODO: Once Manager can return AuthenticatorInfo: Check if only CTAP1 is active
    if tests.is_empty() || tests.contains(&"ctap1") {
        ask_to_de_activate_ctap2(TestCases::CTAP1);
        test_ctap2_code_with_ctap1_token();
    }

    // CTAP2 tests
    // TODO: Once Manager can return AuthenticatorInfo: Check that CTAP2 is active
    if tests.is_empty() || tests.contains(&"ctap2") {
        ask_to_de_activate_ctap2(TestCases::CTAP2);
        // Pre-requisite: Reset token so it doesn't have a PIN set
        reset_ctap2_token();
        test_ctap2_code_with_ctap2_token(None);
        // Repeat tests with known PIN
        set_pin();
        test_ctap2_code_with_ctap2_token(Some(PIN));
        test_ctap2_code_additional_pin_tests();
    }

    if tests.is_empty() || tests.contains(&"multi_tokens") {
        ask_to_de_activate_ctap2(TestCases::MultipleTokens);
        test_ctap2_multiple_tokens();
    }
    println!("SUCCESS! Testsuite done.");
}

fn test_ctap2_code_with_ctap1_token() {
    // Test 1 - Normal sign in with only the key-handle we just registered
    let key_handle = test_ctap2_register_exclude_list(None, CtapVersion::CTAP1);
    test_ctap2_sign_allow_list("https://example.com", vec![key_handle.clone()], None);
    println!("Sign in - OK");

    // Test 2 - Sign in with no key-handle. Should return an error
    let failed_sign = test_sign_raw_result("https://example.com", vec![], None);
    assert!(
        matches!(
            failed_sign,
            Err(AuthenticatorError::HIDError(HIDError::Command(
                CommandError::StatusCode(StatusCode::NoCredentials, ..)
            )))
        ),
        "Got: {:?}",
        failed_sign
    );
    println!("Sign in expectedly failed - OK");

    // Test 3 - Sign in with longer AllowList, only one of which is valid
    test_ctap2_sign_allow_list(
        "https://example.com",
        vec![
            generate_dummy_credential(),
            generate_dummy_credential(),
            key_handle,
            generate_dummy_credential(),
        ],
        None,
    );
    println!("Sign in - OK");

    // Test 4 - Sign in with longer AllowList, all of which are valid
    let key_handles = test_ctap2_register_multiple(None, None, CtapVersion::CTAP1);
    test_ctap2_sign_allow_list("https://multiregister-example.com", key_handles, None);
    println!("Sign in - OK");
}

fn test_ctap2_code_with_ctap2_token(pin: Option<&'static str>) {
    // Test 1 - Normal sign in with only the key-handle we just registered
    let key_handle = test_ctap2_register_exclude_list(pin, CtapVersion::CTAP2);
    test_ctap2_sign_allow_list("https://example.com", vec![key_handle.clone()], pin);
    println!("Sign in - OK");

    // Test 2 - Sign in with no key-handle. Should return an error
    let failed_sign = test_sign_raw_result("https://example.com", vec![], pin);
    assert!(
        matches!(
            failed_sign,
            Err(AuthenticatorError::HIDError(HIDError::Command(
                CommandError::StatusCode(StatusCode::NoCredentials, ..)
            )))
        ),
        "Got: {:?}",
        failed_sign
    );
    println!("Sign in expectedly failed - OK");

    // Test 3 - Sign in with longer AllowList, only one of which is valid
    test_ctap2_sign_allow_list(
        "https://example.com",
        vec![
            generate_dummy_credential(),
            generate_dummy_credential(),
            key_handle,
            generate_dummy_credential(),
        ],
        pin,
    );
    println!("Sign in - OK");

    // Test 4 - Sign in with longer AllowList, all of which are valid
    let key_handles = test_ctap2_register_multiple(None, pin, CtapVersion::CTAP2);
    test_ctap2_sign_allow_list("https://multiregister-example.com", key_handles, pin);
    println!("Sign in - OK");

    // Test 5 - Sign in with longer AllowList, all of which are valid using resident keys
    let key_handles = test_ctap2_register_multiple(Some(true), pin, CtapVersion::CTAP2);
    // With allow list
    test_ctap2_sign_allow_list("https://multiregister-example.com", key_handles, pin);
    // Without allow list
    test_ctap2_sign_allow_list("https://multiregister-example.com", vec![], pin);
    println!("Sign in - OK");
}

fn test_ctap2_code_additional_pin_tests() {
    let (mut manager, timeout_ms) = parse_args_and_setup(CtapVersion::CTAP2);
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    let args = register_args_ctap2("https://example.com", "A. User");
    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        register_tx.send(rv).unwrap();
    }));

    manager
        .register(timeout_ms, args.into(), status_tx, callback)
        .expect("Couldn't register");

    assert!(matches!(
        status_rx.recv(),
        Ok(StatusUpdate::DeviceAvailable { .. })
    ));
    assert!(matches!(
        status_rx.recv(),
        Ok(StatusUpdate::DeviceSelected(..))
    ));
    let sender = extract!(
        status_rx.recv(),
        Ok(StatusUpdate::PinError(PinError::PinRequired, sender)),
        sender
    );
    sender
        .send(Pin::new("wrong PIN"))
        .expect("Failed to send PIN");
    let sender = extract!(
        status_rx.recv(),
        Ok(StatusUpdate::PinError(PinError::InvalidPin(..), sender)),
        sender
    );
    sender
        .send(Pin::new("another wrong PIN"))
        .expect("Failed to send PIN");
    let sender = extract!(
        status_rx.recv(),
        Ok(StatusUpdate::PinError(PinError::InvalidPin(..), sender)),
        sender
    );
    sender.send(Pin::new(PIN)).expect("Failed to send PIN");
    extract!(status_rx.recv(), Ok(StatusUpdate::Success { .. }), ());
    let res = register_rx
        .recv()
        .expect("Problem receiving, unable to continue");

    // Test 1 - Normal register with empty ExcludeList
    let a = extract!(res, Ok(RegisterResult::CTAP2(a, _)), a);
    println!("Additional Test 1: Ok");
    check_attestation_object(&a, Some(PIN), CtapVersion::CTAP2);
}

fn test_ctap2_multiple_tokens() {
    let (mut manager, timeout_ms) = parse_args_and_setup(CtapVersion::CTAP2);
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    let args = register_args_ctap2("https://example.com", "A. User");
    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        register_tx.send(rv).unwrap();
    }));

    manager
        .register(timeout_ms, args.into(), status_tx, callback)
        .expect("Couldn't register");

    for _ in [0, 1] {
        assert!(matches!(
            status_rx.recv(),
            Ok(StatusUpdate::DeviceAvailable { .. })
        ));
    }
    assert!(matches!(
        status_rx.recv(),
        Ok(StatusUpdate::SelectDeviceNotice)
    ));

    println!("Please touch the old token.");
    assert!(matches!(
        status_rx.recv(),
        Ok(StatusUpdate::DeviceSelected(..))
    ));
    let sender = extract!(
        status_rx.recv(),
        Ok(StatusUpdate::PinError(PinError::PinRequired, sender)),
        sender
    );
    sender.send(Pin::new(PIN)).expect("Failed to send PIN");
    extract!(status_rx.recv(), Ok(StatusUpdate::Success { .. }), ());
    let res = register_rx
        .recv()
        .expect("Problem receiving, unable to continue");

    // Test 1 - Normal register with empty ExcludeList
    let a = extract!(res, Ok(RegisterResult::CTAP2(a, _)), a);
    println!("Multitoken test 1: Ok");
    check_attestation_object(&a, Some(PIN), CtapVersion::CTAP2);
}

fn test_ctap2_register_multiple(
    resident_key: Option<bool>,
    pin: Option<&'static str>,
    token_version: CtapVersion,
) -> Vec<PublicKeyCredentialDescriptor> {
    let (mut manager, timeout_ms) = parse_args_and_setup(CtapVersion::CTAP2);
    let status_tx = spawn_normal_status_update_channels(pin);

    // Register 3 different users
    let mut key_handles = Vec::new();
    for username in &["A. User", "A. Nother", "Dr. Who"] {
        let mut args = register_args_ctap2("https://multiregister-example.com", username);
        args.options.resident_key = resident_key;

        let res = ctap2_register(&mut manager, &args, timeout_ms, &status_tx);
        let a = extract!(res, Ok(RegisterResult::CTAP2(a, _)), a);
        check_attestation_object(&a, pin, token_version.clone());
        let handle = a
            .auth_data
            .credential_data
            .expect("No credential data found!")
            .credential_id;
        key_handles.push(PublicKeyCredentialDescriptor {
            id: handle,
            transports: vec![Transport::USB],
        });
        println!("Registering {}: Ok", username);
    }

    key_handles
}

fn test_ctap2_register_exclude_list(
    pin: Option<&'static str>,
    token_version: CtapVersion,
) -> PublicKeyCredentialDescriptor {
    let (mut manager, timeout_ms) = parse_args_and_setup(CtapVersion::CTAP2);
    let status_tx = spawn_normal_status_update_channels(pin);

    // Test 1 - Normal register with empty ExcludeList
    let mut args = register_args_ctap2("https://example.com", "A. User");
    let res = ctap2_register(&mut manager, &args, timeout_ms, &status_tx);
    let a = extract!(res, Ok(RegisterResult::CTAP2(a, _)), a);
    check_attestation_object(&a, pin, token_version.clone());
    println!("Test 1: Ok");

    // Test 2 - Register with already registered key-handle in the ExcludeList
    let registered_key_handle = a.auth_data.credential_data.unwrap().credential_id;
    args.exclude_list = vec![PublicKeyCredentialDescriptor {
        id: registered_key_handle,
        transports: vec![Transport::USB],
    }];
    let res = ctap2_register(&mut manager, &args, timeout_ms, &status_tx);
    extract!(
        res,
        Err(AuthenticatorError::HIDError(HIDError::Command(
            CommandError::StatusCode(StatusCode::CredentialExcluded, None,)
        ))),
        ()
    );
    println!("Test 2: Ok");

    // Test 3 - Register with irrelevant entries in ExcludeList
    args.exclude_list = vec![
        PublicKeyCredentialDescriptor {
            id: vec![0x54; 32],
            transports: vec![Transport::USB],
        },
        PublicKeyCredentialDescriptor {
            id: vec![0x50; 32],
            transports: vec![Transport::USB],
        },
    ];
    let res = ctap2_register(&mut manager, &args, timeout_ms, &status_tx);
    let a = extract!(res, Ok(RegisterResult::CTAP2(a, _)), a);
    check_attestation_object(&a, pin, token_version);
    println!("Test 3: Ok");
    PublicKeyCredentialDescriptor {
        id: a.auth_data.credential_data.unwrap().credential_id,
        transports: vec![Transport::USB],
    }
}

fn test_sign_raw_result(
    origin: &str,
    key_handles: Vec<PublicKeyCredentialDescriptor>,
    pin: Option<&'static str>,
) -> Result<SignResult, AuthenticatorError> {
    let (mut manager, timeout_ms) = parse_args_and_setup(CtapVersion::CTAP2);
    let status_tx = spawn_normal_status_update_channels(pin);

    // Test 1 - Normal sign with AllowList
    let args = sign_args_ctap2(origin, key_handles);

    ctap2_sign(&mut manager, &args, timeout_ms, &status_tx)
}

fn test_ctap2_sign_allow_list(
    origin: &str,
    key_handles: Vec<PublicKeyCredentialDescriptor>,
    pin: Option<&'static str>,
) {
    let res = test_sign_raw_result(origin, key_handles, pin);
    let a = extract!(res, Ok(SignResult::CTAP2(a, _)), a);
    for x in &a.0 {
        assert!(!x
            .credentials
            .as_ref()
            .expect("No credentials!")
            .id
            .is_empty());
        assert!(!x.signature.is_empty());
        assert_eq!(
            x.auth_data.rp_id_hash.0.len(),
            32,
            "Expected rpid-hash to be 32 long, got: {}",
            x.auth_data.rp_id_hash.0.len()
        );
        assert!(x
            .auth_data
            .flags
            .contains(AuthenticatorDataFlags::USER_PRESENT));
        if pin.is_some() {
            assert!(x
                .auth_data
                .flags
                .contains(AuthenticatorDataFlags::USER_VERIFIED));
        } else {
            assert!(!x
                .auth_data
                .flags
                .contains(AuthenticatorDataFlags::USER_VERIFIED));
        }
        assert!(!x.auth_data.flags.contains(AuthenticatorDataFlags::ATTESTED));
    }
}

fn reset_ctap2_token() {
    loop {
        let (mut manager, timeout_ms) = parse_args_and_setup(CtapVersion::CTAP2);
        println!(
        "NOTE: Please unplug all devices, type in 'yes' and plug in the device that should be reset."
    );
        loop {
            let mut s = String::new();
            println!("ATTENTION: Resetting a device will wipe all credentials! Do you wish to continue? [yes/N]");
            std::io::stdin()
                .read_line(&mut s)
                .expect("Did not enter a correct string");
            let trimmed = s.trim();
            if trimmed.is_empty() || trimmed == "N" || trimmed == "n" {
                panic!("Exiting without reset.");
            }
            if trimmed == "y" {
                println!("Please type in the whole word 'yes'");
                continue;
            }
            if trimmed == "yes" {
                break;
            }
        }

        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let (reset_tx, reset_rx) = channel();
        let rs_tx = reset_tx.clone();
        let callback = StateCallback::new(Box::new(move |rv| {
            let _ = rs_tx.send(rv);
        }));

        if let Err(e) = manager.reset(timeout_ms, status_tx.clone(), callback.clone()) {
            panic!("Couldn't register: {:?}", e);
        };

        loop {
            match status_rx.recv() {
                Ok(StatusUpdate::SelectDeviceNotice) => {
                    // Needed to give the tokens enough time to start blinking
                    // otherwise we may cancel pre-maturely and this binary will hang
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    manager.cancel().unwrap();
                    println!("ERROR: Please unplug all other tokens that should not be reset!");
                    continue;
                }
                Ok(StatusUpdate::DeviceSelected(dev_info)) => {
                    debug!("STATUS: Continuing with device: {}", dev_info);
                    break;
                }
                Ok(StatusUpdate::PinError(..)) => panic!("Reset should never ask for a PIN!"),
                Ok(_) => { /* Ignore all other updates */ }
                Err(RecvError) => {
                    panic!("RecvError");
                }
            }
        }

        let reset_result = reset_rx
            .recv()
            .expect("Problem receiving, unable to continue");
        match reset_result {
            Ok(()) => {
                println!("Token successfully reset!");
                break;
            }
            Err(AuthenticatorError::HIDError(HIDError::Command(CommandError::StatusCode(
                StatusCode::NotAllowed,
                _,
            )))) => {
                println!(
                    "Resetting is only allowed within the first 10 seconds after powering up."
                );
                println!("Please unplug your device, plug it back in and try again.");
                continue;
            }
            Err(e) => panic!("Reset failed: {:?}", e),
        };
    }
}

fn set_pin() {
    let (mut manager, timeout_ms) = parse_args_and_setup(CtapVersion::CTAP2);
    let status_tx = spawn_normal_status_update_channels(None);
    let (reset_tx, reset_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        let _ = reset_tx.send(rv);
    }));

    if let Err(e) = manager.set_pin(timeout_ms, Pin::new(PIN), status_tx, callback) {
        panic!("Couldn't call set_pin: {:?}", e);
    };

    let reset_result = reset_rx
        .recv()
        .expect("Problem receiving, unable to continue");
    match reset_result {
        Ok(()) => {
            println!("PIN successfully set!");
        }
        Err(e) => panic!("Setting PIN failed: {:?}", e),
    };
}

fn spawn_normal_status_update_channels(pin: Option<&'static str>) -> Sender<StatusUpdate> {
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::DeviceAvailable { dev_info }) => {
                debug!("STATUS: device available: {}", dev_info)
            }
            Ok(StatusUpdate::DeviceUnavailable { dev_info }) => {
                debug!("STATUS: device unavailable: {}", dev_info)
            }
            Ok(StatusUpdate::Success { dev_info }) => {
                debug!("STATUS: success using device: {}", dev_info);
            }
            Ok(StatusUpdate::SelectDeviceNotice) => {
                println!("STATUS: Please select a device by touching one of them.");
            }
            Ok(StatusUpdate::DeviceSelected(dev_info)) => {
                debug!("STATUS: Continuing with device: {}", dev_info);
            }
            Ok(StatusUpdate::PinError(error, sender)) => match error {
                PinError::PinRequired => {
                    if let Some(pin) = pin {
                        sender.send(Pin::new(pin)).expect("Failed to send PIN");
                    } else {
                        panic!("Was asked for PIN, but should not have been asked!");
                    }
                    continue;
                }
                PinError::InvalidPin(attempts) => {
                    panic!(
                        "PIN was not accepted! (Your token has {} attempts left).",
                        attempts.map_or("unkown".to_string(), |a| format!(
                            "You have {} attempts left.",
                            a
                        ))
                    );
                }
                PinError::PinAuthBlocked => {
                    panic!("Too many failed attempts in one row. Your device has been temporarily blocked. Please unplug it and plug in again.")
                }
                PinError::PinBlocked => {
                    panic!("Too many failed attempts. Your device has been blocked. Reset it.")
                }
                e => {
                    panic!("Unexpected error: {:?}", e)
                }
            },
            Err(RecvError) => {
                debug!("STATUS: end");
                return;
            }
        }
    });
    status_tx
}

fn ctap2_register(
    manager: &mut AuthenticatorService,
    ctap_args: &RegisterArgsCtap2,
    timeout_ms: u64,
    status_tx: &Sender<StatusUpdate>,
) -> Result<RegisterResult, AuthenticatorError> {
    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        register_tx.send(rv).unwrap();
    }));

    if let Err(e) = manager.register(
        timeout_ms,
        ctap_args.clone().into(),
        status_tx.clone(),
        callback,
    ) {
        panic!("Couldn't register: {:?}", e);
    };

    register_rx
        .recv()
        .expect("Problem receiving, unable to continue")
}

fn ctap2_sign(
    manager: &mut AuthenticatorService,
    ctap_args: &SignArgsCtap2,
    timeout_ms: u64,
    status_tx: &Sender<StatusUpdate>,
) -> Result<SignResult, AuthenticatorError> {
    let (sign_tx, sign_rx) = channel();

    let callback = StateCallback::new(Box::new(move |rv| {
        sign_tx.send(rv).unwrap();
    }));

    if let Err(e) = manager.sign(
        timeout_ms,
        ctap_args.clone().into(),
        status_tx.clone(),
        callback,
    ) {
        panic!("Couldn't sign: {:?}", e);
    }

    sign_rx
        .recv()
        .expect("Problem receiving, unable to continue")
}

fn generate_challenge() -> Vec<u8> {
    let mut res = vec![u8::default(); 32];
    rand::thread_rng().fill(&mut res[..]);
    res
}

fn generate_dummy_credential() -> PublicKeyCredentialDescriptor {
    let mut res = vec![0; 32];
    rand::thread_rng().fill(&mut res[..]);
    PublicKeyCredentialDescriptor {
        id: res,
        transports: vec![Transport::USB],
    }
}

fn register_args_ctap2(origin: &str, username: &str) -> RegisterArgsCtap2 {
    let chall_bytes = generate_challenge();
    let user = User {
        id: username.as_bytes().to_vec(),
        icon: None,
        name: Some(username.to_string()),
        display_name: None,
    };

    RegisterArgsCtap2 {
        challenge: chall_bytes,
        relying_party: RelyingParty {
            // Removing https://
            id: origin[8..].to_string(),
            name: None,
            icon: None,
        },
        origin: origin.to_string(),
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
        options: MakeCredentialsOptions {
            resident_key: None,
            user_verification: None,
        },
        extensions: Default::default(),
        pin: None,
    }
}

fn sign_args_ctap2(origin: &str, allow_list: Vec<PublicKeyCredentialDescriptor>) -> SignArgsCtap2 {
    let chall_bytes = generate_challenge();
    SignArgsCtap2 {
        challenge: chall_bytes,
        origin: origin.to_string(),
        relying_party_id: origin[8..].to_string(),
        allow_list,
        options: GetAssertionOptions::default(),
        extensions: Default::default(),
        // GetAssertionExtensions {
        //        hmac_secret: None,
        //    },
        pin: None,
    }
}

fn parse_command_line_options() -> (String, Options, Matches) {
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
    opts.optopt(
        "t",
        "tests",
        "Which tests should be run. Seperated by commas. Default: ctap1,ctap2,multi_tokens",
        "TESTS",
    );
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!("{}", f.to_string()),
    };

    if matches.opt_present("help") {
        print_usage(&program, opts);
        panic!();
    }

    (program, opts, matches)
}

fn parse_args_and_setup(ctap_version: CtapVersion) -> (AuthenticatorService, u64) {
    let (program, opts, matches) = parse_command_line_options();
    let mut manager =
        AuthenticatorService::new(ctap_version).expect("The auth service should initialize safely");

    if !matches.opt_present("no-u2f-usb-hid") {
        manager.add_u2f_usb_hid_platform_transports();
    }

    let timeout_ms = match matches.opt_get_default::<u64>("timeout", 15) {
        Ok(timeout_s) => {
            debug!("Using {}s as the timeout", &timeout_s);
            timeout_s * 1_000
        }
        Err(e) => {
            println!("{}", e);
            print_usage(&program, opts);
            panic!();
        }
    };
    (manager, timeout_ms)
}

fn check_attestation_object(
    res: &AttestationObject,
    pin: Option<&'static str>,
    token_version: CtapVersion,
) {
    let cred_data = res
        .auth_data
        .credential_data
        .as_ref()
        .expect("No credential data found!");
    assert!(!cred_data.credential_id.is_empty());
    assert!(res
        .auth_data
        .flags
        .contains(AuthenticatorDataFlags::USER_PRESENT));
    assert!(res
        .auth_data
        .flags
        .contains(AuthenticatorDataFlags::ATTESTED));
    if pin.is_some() {
        // User verified with PIN was provided, otherwise not
        assert!(res
            .auth_data
            .flags
            .contains(AuthenticatorDataFlags::USER_VERIFIED));
    } else {
        assert!(!res
            .auth_data
            .flags
            .contains(AuthenticatorDataFlags::USER_VERIFIED));
    }
    // Check that the RP-id has the right length
    assert_eq!(
        res.auth_data.rp_id_hash.0.len(),
        32,
        "Expected rpid-hash to be 32 long, got: {}",
        res.auth_data.rp_id_hash.0.len()
    );
    if token_version == CtapVersion::CTAP1 {
        // Check that AAGUID is all zeros
        assert!(cred_data.aaguid.0.iter().any(|x| *x == 0));
    } else {
        // Check that AAGUID is not all zeros
        assert!(cred_data.aaguid.0.iter().any(|x| *x != 0));
    }
}

fn ask_to_de_activate_ctap2(tests: TestCases) {
    println!("------------------------------------------------------------------------");
    let print_single_token = |first, second| {
        println!("Please plug in a token {first} or {second} CTAP2 on your token!");
    };
    match tests {
        TestCases::CTAP1 => print_single_token("without CTAP2", "DEactivate"),
        TestCases::CTAP2 => print_single_token("with CTAP2", "activate"),
        TestCases::MultipleTokens => {
            println!("Please plug in two CTAP2 tokens! And always select the old one.")
        }
    }
    println!("------------------------------------------------------------------------");
    println!("Press Return to continue...");

    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
}

enum TestCases {
    CTAP1,
    CTAP2,
    MultipleTokens,
}
