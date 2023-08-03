/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use authenticator::{
    authenticatorservice::AuthenticatorService,
    ctap2::{
        commands::{
            authenticator_config::{AuthConfigCommand, SetMinPINLength},
            bio_enrollment::BioTemplateId,
        },
        server::{PublicKeyCredentialDescriptor, User},
    },
    errors::AuthenticatorError,
    statecallback::StateCallback,
    AuthenticatorInfo, BioEnrollmentCmd, BioEnrollmentResult, CredManagementCmd,
    CredentialManagementResult, InteractiveRequest, InteractiveUpdate, ManageResult, Pin,
    StatusPinUv, StatusUpdate,
};
use getopts::Options;
use log::debug;
use std::{
    env, io,
    sync::{mpsc::Sender, Arc, Mutex},
    thread,
};
use std::{
    fmt::Display,
    io::Write,
    sync::mpsc::{channel, Receiver, RecvError},
};

#[derive(Debug, Clone, PartialEq)]
enum Operation {
    Quit,
    ShowFullInfo(AuthenticatorInfo),
    Reset,
    Pin(PinOperation),
    Configure(ConfigureOperation),
    Credentials(CredentialsOperation),
    Bio(BioOperation),
}

impl Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Quit => write!(f, "Quit"),
            Operation::ShowFullInfo(_) => write!(f, "Show full info"),
            Operation::Reset => write!(f, "Reset"),
            Operation::Pin(PinOperation::Change) => write!(f, "Change Pin"),
            Operation::Pin(PinOperation::Set) => write!(f, "Set Pin"),
            Operation::Configure(_) => write!(f, "Configure Authenticator"),
            Operation::Credentials(_) => write!(f, "Manage Credentials"),
            Operation::Bio(_) => write!(f, "Manage BioEnrollments"),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
enum PinOperation {
    Set,
    Change,
}

#[derive(Debug, Clone, PartialEq)]
enum ConfigureOperation {
    ToggleAlwaysUV,
    EnableEnterpriseAttestation,
    SetMinPINLength,
}

impl Display for ConfigureOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigureOperation::ToggleAlwaysUV => write!(f, "Toggle option 'Always UV'"),
            ConfigureOperation::EnableEnterpriseAttestation => {
                write!(f, "Enable Enterprise attestation")
            }
            ConfigureOperation::SetMinPINLength => write!(f, "Set min. PIN length"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum CredentialsOperation {
    List,
    Delete(Option<PublicKeyCredentialDescriptor>),
    UpdateUser(Option<(PublicKeyCredentialDescriptor, User)>),
}

impl Display for CredentialsOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialsOperation::List => write!(f, "List credentials"),
            CredentialsOperation::Delete(_) => write!(f, "Delete credentials"),
            CredentialsOperation::UpdateUser(_) => write!(f, "Update user info"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum BioOperation {
    ShowInfo,
    Add,
    List,
    Delete(Option<BioTemplateId>),
    Rename(Option<(BioTemplateId, String)>),
}

impl Display for BioOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BioOperation::ShowInfo => write!(f, "Show fingerprint sensor info"),
            BioOperation::List => write!(f, "List enrollments"),
            BioOperation::Add => write!(f, "Add enrollment"),
            BioOperation::Delete(_) => write!(f, "Delete enrollment"),
            BioOperation::Rename(_) => write!(f, "Rename enrollment"),
        }
    }
}

struct PossibleOperations {
    general_ops: Vec<Operation>,
    configure_ops: Vec<ConfigureOperation>,
    credentials_ops: Vec<CredentialsOperation>,
    bio_ops: Vec<BioOperation>,
}

impl PossibleOperations {
    fn ask_user(&self) -> Operation {
        let top_level = self.get_top_level_ops();
        println!("What do you wish to do?");
        let choice = ask_user_choice(&top_level);
        match &top_level[choice] {
            Operation::Configure(_) => {
                println!("Which configure operation?");
                let subchoice = ask_user_choice(&self.configure_ops);
                Operation::Configure(self.configure_ops[subchoice].clone())
            }
            Operation::Credentials(_) => {
                println!("Which credential management operation?");
                let subchoice = ask_user_choice(&self.credentials_ops);
                Operation::Credentials(self.credentials_ops[subchoice].clone())
            }
            Operation::Bio(_) => {
                println!("Which bio enrollment operation?");
                let subchoice = ask_user_choice(&self.bio_ops);
                Operation::Bio(self.bio_ops[subchoice].clone())
            }
            x => x.clone(),
        }
    }

    fn get_top_level_ops(&self) -> Vec<Operation> {
        let mut ops = self.general_ops.clone();
        if !self.configure_ops.is_empty() {
            // We don't really care what specific Operation this is
            ops.push(Operation::Configure(ConfigureOperation::ToggleAlwaysUV));
        }
        if !self.credentials_ops.is_empty() {
            ops.push(Operation::Credentials(CredentialsOperation::List));
        }
        if !self.bio_ops.is_empty() {
            ops.push(Operation::Bio(BioOperation::Add));
        }
        ops
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {program} [options]");
    print!("{}", opts.usage(&brief));
}

fn parse_possible_operations(info: &AuthenticatorInfo) -> PossibleOperations {
    let mut general_ops = vec![Operation::Quit];
    general_ops.push(Operation::Reset);
    general_ops.push(Operation::ShowFullInfo(info.clone()));

    // PIN-related
    match info.options.client_pin {
        None => {}
        Some(true) => general_ops.push(Operation::Pin(PinOperation::Change)),
        Some(false) => general_ops.push(Operation::Pin(PinOperation::Set)),
    }

    // Authenticator-Configuration
    let mut configure_ops = vec![];
    if info.options.authnr_cfg == Some(true) && info.options.always_uv.is_some() {
        configure_ops.push(ConfigureOperation::ToggleAlwaysUV);
    }
    if info.options.authnr_cfg == Some(true) && info.options.set_min_pin_length.is_some() {
        configure_ops.push(ConfigureOperation::SetMinPINLength);
    }
    if info.options.ep.is_some() {
        configure_ops.push(ConfigureOperation::EnableEnterpriseAttestation);
    }

    // Credential Management
    let mut credentials_ops = vec![];
    if info.options.cred_mgmt == Some(true) || info.options.credential_mgmt_preview == Some(true) {
        credentials_ops.extend([
            CredentialsOperation::List,
            CredentialsOperation::Delete(None),
            CredentialsOperation::UpdateUser(None),
        ]);
    }

    // Bio Enrollment
    let mut bio_ops = vec![];
    if info.options.bio_enroll.is_some() || info.options.user_verification_mgmt_preview.is_some() {
        bio_ops.extend([BioOperation::ShowInfo, BioOperation::Add]);
    }
    if info.options.bio_enroll == Some(true)
        || info.options.user_verification_mgmt_preview == Some(true)
    {
        bio_ops.extend([
            BioOperation::Delete(None),
            BioOperation::List,
            BioOperation::Rename(None),
        ]);
    }
    PossibleOperations {
        general_ops,
        configure_ops,
        credentials_ops,
        bio_ops,
    }
}

fn ask_user_choice<T: Display>(choices: &[T]) -> usize {
    for (idx, op) in choices.iter().enumerate() {
        println!("({idx}) {op}");
    }

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
                return idx;
            }
        }
    }
}

fn execute_chosen_operation(operation: &Operation, tx: Sender<InteractiveRequest>) {
    match operation {
        Operation::Quit => {
            return;
        }
        Operation::ShowFullInfo(info) => println!("Authenticator Info {:#?}", info),
        Operation::Reset => tx
            .send(InteractiveRequest::Reset)
            .expect("Failed to send Reset request."),
        Operation::Pin(op) => {
            let raw_new_pin =
                rpassword::prompt_password_stderr("Enter new PIN: ").expect("Failed to read PIN");
            let new_pin = Pin::new(&raw_new_pin);
            if *op == PinOperation::Change {
                let raw_curr_pin = rpassword::prompt_password_stderr("Enter current PIN: ")
                    .expect("Failed to read PIN");
                let curr_pin = Pin::new(&raw_curr_pin);
                tx.send(InteractiveRequest::ChangePIN(curr_pin, new_pin))
                    .expect("Failed to send PIN-change request");
            } else {
                tx.send(InteractiveRequest::SetPIN(new_pin))
                    .expect("Failed to send PIN-set request");
            }
        }
        Operation::Configure(ConfigureOperation::ToggleAlwaysUV) => {
            tx.send(InteractiveRequest::ChangeConfig(
                AuthConfigCommand::ToggleAlwaysUv,
            ))
            .expect("Failed to send ToggleAlwaysUV request.");
        }
        Operation::Configure(ConfigureOperation::EnableEnterpriseAttestation) => {
            tx.send(InteractiveRequest::ChangeConfig(
                AuthConfigCommand::EnableEnterpriseAttestation,
            ))
            .expect("Failed to send EnableEnterpriseAttestation request.");
        }
        Operation::Configure(ConfigureOperation::SetMinPINLength) => {
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
            .expect("Failed to send SetMinPINLength request.");
        }
        Operation::Credentials(CredentialsOperation::List)
        | Operation::Credentials(CredentialsOperation::Delete(None))
        | Operation::Credentials(CredentialsOperation::UpdateUser(None)) => {
            tx.send(InteractiveRequest::CredentialManagement(
                CredManagementCmd::GetCredentials,
            ))
            .expect("Failed to send GetCredentials request.");
        }
        Operation::Credentials(CredentialsOperation::Delete(Some(id))) => {
            tx.send(InteractiveRequest::CredentialManagement(
                CredManagementCmd::DeleteCredential(id.clone()),
            ))
            .expect("Failed to send DeleteCredentials request.");
        }
        Operation::Credentials(CredentialsOperation::UpdateUser(Some((id, user)))) => {
            tx.send(InteractiveRequest::CredentialManagement(
                CredManagementCmd::UpdateUserInformation((id.clone(), user.clone())),
            ))
            .expect("Failed to send UpdateUserinformation request.");
        }
        Operation::Bio(BioOperation::Add) => {
            let mut input = String::new();
            print!(
                "The name of the new bio enrollment (leave empty if you don't want to name it): "
            );
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
            .expect("Failed to send StartNewEnrollment request.");
        }
        Operation::Bio(BioOperation::List)
        | Operation::Bio(BioOperation::Delete(None))
        | Operation::Bio(BioOperation::Rename(None)) => {
            tx.send(InteractiveRequest::BioEnrollment(
                BioEnrollmentCmd::GetEnrollments,
            ))
            .expect("Failed to send GetEnrollments request.");
        }
        Operation::Bio(BioOperation::Delete(Some(id))) => {
            tx.send(InteractiveRequest::BioEnrollment(
                BioEnrollmentCmd::DeleteEnrollment(id.clone()),
            ))
            .expect("Failed to send GetEnrollments request.");
        }
        Operation::Bio(BioOperation::Rename(Some((id, name)))) => {
            tx.send(InteractiveRequest::BioEnrollment(
                BioEnrollmentCmd::ChangeName((id.clone(), name.clone())),
            ))
            .expect("Failed to send GetEnrollments request.");
        }
        Operation::Bio(BioOperation::ShowInfo) => {
            tx.send(InteractiveRequest::BioEnrollment(
                BioEnrollmentCmd::GetFingerprintSensorInfo,
            ))
            .expect("Failed to send GetFingerprintSensorInfo request.");
        }
    }
}

fn interactive_status_callback(
    status_rx: Receiver<StatusUpdate>,
    last_user_choice: Arc<Mutex<Operation>>,
) {
    loop {
        match status_rx.recv() {
            Ok(StatusUpdate::InteractiveManagement(InteractiveUpdate::StartManagement((
                tx,
                auth_info,
            )))) => {
                let info = match auth_info {
                    Some(info) => info,
                    None => {
                        println!("Device only supports CTAP1 and can't be managed.");
                        return;
                    }
                };
                let last_choice = last_user_choice.lock().unwrap().clone();
                let operation = match last_choice {
                    Operation::Quit => {
                        let operations = parse_possible_operations(&info);
                        let choice = operations.ask_user();
                        *last_user_choice.lock().unwrap() = choice.clone();
                        choice
                    }
                    operation => operation.clone(),
                };
                execute_chosen_operation(&operation, tx);
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

    let last_user_choice = Arc::new(Mutex::new(Operation::Quit));
    loop {
        let user_choice_clone = last_user_choice.clone();
        let (status_tx, status_rx) = channel::<StatusUpdate>();
        thread::spawn(move || interactive_status_callback(status_rx, user_choice_clone));

        let (manage_tx, manage_rx) = channel();
        let state_callback =
            StateCallback::<Result<ManageResult, AuthenticatorError>>::new(Box::new(move |rv| {
                manage_tx.send(rv).unwrap();
            }));

        match manager.manage(timeout_ms, status_tx, state_callback) {
            Ok(_) => {
                debug!("Started management");
            }
            Err(e) => {
                println!("Error! Failed to start interactive management: {:?}", e);
                return;
            }
        }
        let manage_result = manage_rx
            .recv()
            .expect("Problem receiving, unable to continue");
        let last_choice = last_user_choice.lock().unwrap().clone();
        match manage_result {
            Ok(ManageResult::CredManagement(CredentialManagementResult::CredentialList(
                credlist,
            ))) if last_choice == Operation::Credentials(CredentialsOperation::Delete(None))
                || last_choice
                    == Operation::Credentials(CredentialsOperation::UpdateUser(None)) =>
            {
                let mut creds = vec![];
                for rp in credlist.credential_list {
                    for cred in rp.credentials {
                        creds.push((rp.rp.name.clone(), cred.user, cred.credential_id));
                    }
                }
                let display_creds: Vec<_> = creds
                    .iter()
                    .map(|(rp, user, id)| format!("{:?} - {:?} - {:?}", rp, user, id))
                    .collect();
                let choice = ask_user_choice(&display_creds);
                if last_choice == Operation::Credentials(CredentialsOperation::Delete(None)) {
                    *last_user_choice.lock().unwrap() = Operation::Credentials(
                        CredentialsOperation::Delete(Some(creds[choice].2.clone())),
                    );
                    continue;
                } else {
                    // Updating username. Asking for the new one.
                    let mut input = String::new();
                    print!("New username: ");
                    io::stdout()
                        .lock()
                        .flush()
                        .expect("Failed to flush stdout!");
                    io::stdin()
                        .read_line(&mut input)
                        .expect("error: unable to read user input");
                    input = input.trim().to_string();
                    let name = if input.is_empty() { None } else { Some(input) };
                    let mut new_user = creds[choice].1.clone();
                    new_user.name = name;
                    *last_user_choice.lock().unwrap() = Operation::Credentials(
                        CredentialsOperation::UpdateUser(Some((creds[choice].2.clone(), new_user))),
                    );
                    continue;
                }
            }
            Ok(ManageResult::BioEnrollment(BioEnrollmentResult::EnrollmentList(biolist)))
                if last_choice == Operation::Bio(BioOperation::Delete(None))
                    || last_choice == Operation::Bio(BioOperation::Rename(None)) =>
            {
                let display_bios: Vec<_> = biolist
                    .iter()
                    .map(|x| format!("{:?} - {:?}", x.template_friendly_name, x.template_id))
                    .collect();
                let choice = ask_user_choice(&display_bios);
                if last_choice == Operation::Bio(BioOperation::Delete(None)) {
                    *last_user_choice.lock().unwrap() = Operation::Bio(BioOperation::Delete(Some(
                        biolist[choice].template_id.clone(),
                    )));
                    continue;
                } else {
                    // Updating enrollment name. Asking for the new one.
                    let mut input = String::new();
                    print!("New name: ");
                    io::stdout()
                        .lock()
                        .flush()
                        .expect("Failed to flush stdout!");
                    io::stdin()
                        .read_line(&mut input)
                        .expect("error: unable to read user input");
                    let name = input.trim().to_string();
                    *last_user_choice.lock().unwrap() = Operation::Bio(BioOperation::Rename(Some(
                        (biolist[choice].template_id.clone(), name),
                    )));
                    continue;
                }
            }
            Ok(r) => {
                println!("Success! Result = {r:?}");
                break;
            }
            Err(e) => {
                println!("Error! {:?}", e);
                break;
            }
        };
    }
    println!("Done");
}
