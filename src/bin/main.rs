#[macro_use]
extern crate crypto;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
extern crate base64;
extern crate u2fhid;
use std::{io, thread, time};
use std::io::{Read, Write};
use std::sync::mpsc::{channel, Sender, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use u2fhid::U2FDevice;

const PARAMETER_SIZE : usize = 32;

enum Command {
    Register,
    Sign,
}

pub struct WorkUnit
{
    timeout: Duration,
    start_time: Instant,
    command: Command,
    challenge: Vec<u8>,
    application: Vec<u8>,
    key_handle: Option<Vec<u8>>,
    result_tx: Sender<io::Result<Vec<u8>>>
}

pub struct U2FManager {
    work_tx: Sender<WorkUnit>,
}

pub fn open_u2f_manager() -> io::Result<U2FManager> {
    let (mut tx, rx) = channel::<WorkUnit>();
    let manager = U2FManager{
        work_tx: tx,
    };

    if let Err(e) = thread::Builder::new().name("HID Runloop".to_string()).spawn(move || {
        U2FManager::worker_loop(rx);
    }) {
        return Err(e);
    }
    Ok(manager)
}

impl U2FManager {
    fn worker_loop(work_rx: Receiver<WorkUnit>) {
        let platform = match u2fhid::platform::open_platform_manager() {
            Ok(v) => v,
            Err(e) => panic!("Failure to open platform HID support: {}", e),
        };

        let mut current_job : Option<WorkUnit> = None;
        loop {
            println!("Doing work");

            // Get new work
            match work_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(v) => {
                    // TODO: Cancel existing job?
                    current_job = Some(v)
                },
                Err(e) => {
                    if e != RecvTimeoutError::Timeout {
                        panic!("whoa now {}", e);
                    }
                },
            };

            current_job = match current_job {
                Some(job) => {
                    let mut done = false;
                    let security_keys = match platform.find_keys() {
                        Ok(v) => v,
                        Err(e) => panic!("Problem enumerating keys, {}", e),
                    };

                    for mut device_obj in security_keys {
                        println!("iterating now");
                        if let Ok(_) = U2FManager::perform_job_for_key(&mut device_obj, &job) {
                            done = true;
                            break;
                        }
                    }

                    if job.start_time.elapsed() > job.timeout {
                        job.result_tx.send(Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out")));
                        done = true;
                    }

                    if done {
                        None
                    } else {
                        Some(job)
                    }
                },
                None => None, // Nothing to do
            }
        }
    }

    pub fn perform_job_for_key<T>(dev: &mut T, job: &WorkUnit) -> io::Result<()>
        where T: U2FDevice + Read + Write
    {
        let result = match job.command {
            Command::Register => {
                u2fhid::u2f_register(dev, &job.challenge, &job.application)
            },
            Command::Sign => {
                // It'd be an error if key_handle was None here
                let keybytes = job.key_handle.as_ref().unwrap();
                u2fhid::u2f_sign(dev, &job.challenge, &job.application, keybytes)
            },
        };

        match result {
            Ok(bytes) => {
                job.result_tx.send(Ok(bytes));
                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    pub fn register<F>(&self, timeout_sec: u8, challenge: Vec<u8>, application: Vec<u8>, callback: F)
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
            callback(Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes")));
            return;
        }

        let (result_tx, result_rx) = channel::<io::Result<Vec<u8>>>();

        if let Err(e) = self.work_tx.send(WorkUnit{
            timeout: Duration::from_secs(timeout_sec as u64),
            start_time: Instant::now(),
            command: Command::Register,
            challenge: challenge,
            application: application,
            key_handle: None,
            result_tx: result_tx,
        }) {
            callback(Err(io::Error::new(io::ErrorKind::Other, format!("Send error {}", e))));
            return;
        }

        match result_rx.recv() {
            Ok(v) => callback(v),
            Err(e) => callback(Err(io::Error::new(io::ErrorKind::Other, e))),
        }
    }

    pub fn sign<F>(&self, timeout_sec: u8, challenge: Vec<u8>, application: Vec<u8>, key_handle: Vec<u8>, callback: F)
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
            callback(Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes")));
            return;
        }

    }
}

fn u2f_get_key_handle_from_register_response(register_response: &Vec<u8>) -> io::Result<Vec<u8>>
{
    if register_response[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Reserved byte not set correctly"));
    }

    let key_handle_len = register_response[66] as usize;
    let mut public_key = register_response.clone();
    let mut key_handle = public_key.split_off(67);
    // let attestation = key_handle.split_off(key_handle_len);

    Ok(key_handle)
}

fn main() {
    println!("Searching for keys...");

    let mut challenge = Sha256::new();
    challenge.input_str(r#"{"challenge": "1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70", "version": "U2F_V2", "appId": "http://demo.yubico.com"}"#);
    let mut chall_bytes: Vec<u8> = vec![0; challenge.output_bytes()];
    challenge.result(&mut chall_bytes);

    let mut application = Sha256::new();
    application.input_str("http://demo.yubico.com");
    let mut app_bytes: Vec<u8> = vec![0; application.output_bytes()];
    application.result(&mut app_bytes);

    let (tx, rx) = channel();
    let manager = open_u2f_manager().unwrap();

    manager.register(15, chall_bytes, app_bytes, move |result| {
        // Ship back to the main thread
        if let Err(e) = tx.send(result) {
            panic!("Could not send: {}", e);
        }
    });

    let thread_result = match rx.recv() {
        Ok(v) => v,
        Err(e) => panic!("Couldn't read data: {}", e),
    };

    let register_data = match thread_result {
        Ok(v) => v,
        Err(e) => panic!("Register failure: {}", e),
    };

    println!("Register result: {}", base64::encode(&register_data));

    // let key_handle = u2f_get_key_handle_from_register_response(&register_data).unwrap();

    // let mut chall_bytes: Vec<u8> = vec![0; challenge.output_bytes()];
    // challenge.result(&mut chall_bytes);
    // let mut app_bytes: Vec<u8> = vec![0; application.output_bytes()];
    // application.result(&mut app_bytes);

    // manager.sign(15, chall_bytes, app_bytes, key_handle, move|result| {
    //     println!("Sign result: {}", base64::encode(&result.unwrap()));
    // });

    println!("Done.");
}
