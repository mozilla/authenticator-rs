/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use authenticator::{
    authenticatorservice::AuthenticatorService,
    ctap2::commands::authenticator_config::{AuthConfigCommand, SetMinPINLength},
    errors::AuthenticatorError,
    statecallback::StateCallback,
    BioEnrollmentCmd, CredManagementCmd, InteractiveRequest, InteractiveUpdate, ManageResult, Pin,
    StatusPinUv, StatusUpdate,
};
use getopts::Options;
use log::debug;
use std::{env, io, thread};
use std::{
    io::Write,
    sync::mpsc::{channel, Receiver, RecvError},
};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {program} [options]");
    print!("{}", opts.usage(&brief));
}

fn interactive_status_callback(status_rx: Receiver<StatusUpdate>) {
    loop {
        match status_rx.recv() {
            Ok(StatusUpdate::InteractiveManagement(InteractiveUpdate::StartManagement((
                tx,
                auth_info,
            )))) => {
                debug!("STATUS: interactive management: {:#?}", auth_info);
                let mut change_pin = false;
                if let Some(info) = auth_info {
                    println!("Authenticator Info {:#?}", info);
                    println!();
                    println!("What do you wish to do?");

                    let mut choices = vec!["0", "1"];
                    println!("(0) Quit");
                    println!("(1) Reset token");
                    match info.options.client_pin {
                        None => {}
                        Some(true) => {
                            println!("(2) Change PIN");
                            choices.push("2");
                            change_pin = true;
                        }
                        Some(false) => {
                            println!("(2) Set PIN");
                            choices.push("2");
                        }
                    }
                    if info.options.authnr_cfg == Some(true) && info.options.always_uv.is_some() {
                        println!("(3) Toggle 'Always UV'");
                        choices.push("3");
                    }
                    if info.options.authnr_cfg == Some(true)
                        && info.options.set_min_pin_length.is_some()
                    {
                        println!("(4) Set min. PIN length");
                        choices.push("4");
                    }
                    if info.options.cred_mgmt == Some(true)
                        || info.options.credential_mgmt_preview == Some(true)
                    {
                        println!("(5) Credential Management");
                        choices.push("5");
                    }
                    if info.options.bio_enroll == Some(true)
                        || info.options.user_verification_mgmt_preview == Some(true)
                    {
                        println!("(6) List bio enrollments");
                        choices.push("6");
                    }
                    if info.options.bio_enroll.is_some()
                        || info.options.user_verification_mgmt_preview.is_some()
                    {
                        println!("(7) Add bio enrollment");
                        choices.push("7");
                    }

                    let mut input = String::new();
                    while !choices.contains(&input.trim()) {
                        input.clear();
                        print!("Your choice: ");
                        io::stdout()
                            .lock()
                            .flush()
                            .expect("Failed to flush stdout!");
                        io::stdin()
                            .read_line(&mut input)
                            .expect("error: unable to read user input");
                    }
                    input = input.trim().to_string();

                    match input.as_str() {
                        "0" => {
                            return;
                        }
                        "1" => {
                            tx.send(InteractiveRequest::Reset)
                                .expect("Failed to send Reset request.");
                        }
                        "2" => {
                            let raw_new_pin = rpassword::prompt_password_stderr("Enter new PIN: ")
                                .expect("Failed to read PIN");
                            let new_pin = Pin::new(&raw_new_pin);
                            if change_pin {
                                let raw_curr_pin =
                                    rpassword::prompt_password_stderr("Enter current PIN: ")
                                        .expect("Failed to read PIN");
                                let curr_pin = Pin::new(&raw_curr_pin);
                                tx.send(InteractiveRequest::ChangePIN(curr_pin, new_pin))
                                    .expect("Failed to send PIN-change request");
                            } else {
                                tx.send(InteractiveRequest::SetPIN(new_pin))
                                    .expect("Failed to send PIN-set request");
                            }
                            return;
                        }
                        "3" => {
                            tx.send(InteractiveRequest::ChangeConfig(
                                AuthConfigCommand::ToggleAlwaysUv,
                            ))
                            .expect("Failed to send Reset request.");
                        }
                        "4" => {
                            let mut length = String::new();
                            while length.trim().parse::<u64>().is_err() {
                                length.clear();
                                print!("New minimum PIN length: ");
                                io::stdout()
                                    .lock()
                                    .flush()
                                    .expect("Failed to flush stdout!");
                                io::stdin()
                                    .read_line(&mut length)
                                    .expect("error: unable to read user input");
                            }
                            let new_length = length.trim().parse::<u64>().unwrap();
                            let cmd = SetMinPINLength {
                                new_min_pin_length: Some(new_length),
                                min_pin_length_rpids: None,
                                force_change_pin: None,
                            };

                            tx.send(InteractiveRequest::ChangeConfig(
                                AuthConfigCommand::SetMinPINLength(cmd),
                            ))
                            .expect("Failed to send Reset request.");
                        }
                        "5" => {
                            tx.send(InteractiveRequest::CredentialManagement(
                                CredManagementCmd::GetCredentials,
                            ))
                            .expect("Failed to send Reset request.");
                        }
                        "6" => {
                            tx.send(InteractiveRequest::BioEnrollment(
                                BioEnrollmentCmd::GetEnrollments,
                            ))
                            .expect("Failed to send Reset request.");
                        }
                        "7" => {
                            let mut input = String::new();
                            print!("The name of the new bio enrollment (leave empty if you don't want to name it): ");
                            io::stdout()
                                .lock()
                                .flush()
                                .expect("Failed to flush stdout!");
                            io::stdin()
                                .read_line(&mut input)
                                .expect("error: unable to read user input");
                            input = input.trim().to_string();
                            let name = if input.is_empty() { None } else { Some(input) };
                            tx.send(InteractiveRequest::BioEnrollment(
                                BioEnrollmentCmd::StartNewEnrollment(name),
                            ))
                            .expect("Failed to send Reset request.");
                        }
                        _ => {
                            panic!("Can't happen");
                        }
                    }
                } else {
                    println!("Device only supports CTAP1 and can't be managed.");
                }
            }
            Ok(StatusUpdate::InteractiveManagement(InteractiveUpdate::BioEnrollmentUpdate((
                last_sample_status,
                remaining_samples,
            )))) => {
                println!("Last sample status: {last_sample_status:?}, remaining samples: {remaining_samples:?}");
            }
            Ok(StatusUpdate::SelectDeviceNotice) => {
                println!("STATUS: Please select a device by touching one of them.");
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
            Ok(StatusUpdate::PresenceRequired) => {
                println!("Please touch your device!");
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
    }
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

    let mut manager =
        AuthenticatorService::new().expect("The auth service should initialize safely");

    if !matches.opt_present("no-u2f-usb-hid") {
        manager.add_u2f_usb_hid_platform_transports();
    }

    let timeout_ms = match matches.opt_get_default::<u64>("timeout", 120) {
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

    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || interactive_status_callback(status_rx));

    let (manage_tx, manage_rx) = channel();
    let state_callback =
        StateCallback::<Result<ManageResult, AuthenticatorError>>::new(Box::new(move |rv| {
            manage_tx.send(rv).unwrap();
        }));

    match manager.manage(timeout_ms, status_tx, state_callback) {
        Ok(_) => {
            debug!("Started management")
        }
        Err(e) => {
            println!("Error! Failed to start interactive management: {:?}", e)
        }
    }
    let manage_result = manage_rx
        .recv()
        .expect("Problem receiving, unable to continue");
    match manage_result {
        Ok(r) => println!("Success! Result = {r:?}"),
        Err(e) => println!("Error! {:?}", e),
    };
    println!("Done");
}
