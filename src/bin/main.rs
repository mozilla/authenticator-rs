#[macro_use]
extern crate crypto;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
extern crate base64;
extern crate u2fhid;
use std::{io, thread, time};
use std::sync::mpsc::channel;
use std::time::Duration;
use u2fhid::U2FDevice;

const PARAMETER_SIZE : usize = 32;

pub struct U2FManager {
}

impl U2FManager {
    pub fn new() -> U2FManager {
        U2FManager{}
    }

    pub fn register<F>(&self, timeout_sec: u8, challenge: Vec<u8>, application: Vec<u8>, callback: F)
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
            callback(Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes")));
            return;
        }

        let timeout = Duration::from_secs(timeout_sec as u64);

        thread::Builder::new().name("Register Runloop".to_string()).spawn(move || {
            let mut manager = u2fhid::platform::new();
            let result = manager.register(timeout, challenge, application);
            callback(result);
        });
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
    let manager = U2FManager::new();

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
