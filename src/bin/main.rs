#[macro_use]
extern crate crypto;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
extern crate u2fhid;
use std::{io, ffi};
extern crate base64;

const PARAMETER_SIZE : usize = 32;

fn register_and_sign(hid_manager: &u2fhid::platform::U2FManager) -> io::Result<Vec<u8>>
{
    let mut challenge = Sha256::new();
    challenge.input_str(r#"{"challenge": "1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70", "version": "U2F_V2", "appId": "http://demo.yubico.com"}"#);
    let mut chall_bytes: Vec<u8> = vec![0; challenge.output_bytes()];
    challenge.result(&mut chall_bytes);

    let mut application = Sha256::new();
    application.input_str("http://demo.yubico.com");
    let mut app_bytes: Vec<u8> = vec![0; application.output_bytes()];
    application.result(&mut app_bytes);

    println!("Register: challenge={} application={}", base64::encode(&chall_bytes), base64::encode(&app_bytes));

    let register_response = try!(u2f_register(&hid_manager, 15, &chall_bytes, &app_bytes));

    let key_handle = try!(u2f_get_key_handle_from_register_response(&register_response));

    let sign_response = try!(u2f_sign(&hid_manager, 15, &chall_bytes, &app_bytes, &key_handle));

    Ok(sign_response)
}

fn u2f_get_key_handle_from_register_response(register_response: &Vec<u8>) -> io::Result<Vec<u8>>
{
    println!("Register Response: {}", base64::encode(register_response));

    if register_response[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Reserved byte not set correctly"));
    }

    let key_handle_len = register_response[66] as usize;
    let mut public_key = register_response.clone();
    let mut key_handle = public_key.split_off(67);
    let attestation = key_handle.split_off(key_handle_len);

    println!("Key Handle ({}): {}", key_handle.len(), base64::encode(&key_handle));
    println!("Attestation ({}): {}", attestation.len(), base64::encode(&attestation));

    Ok(key_handle)
}

fn u2f_register(hid_manager: &u2fhid::platform::U2FManager, timeout_sec: u8, challenge: &Vec<u8>, application: &Vec<u8>) -> io::Result<Vec<u8>>
{
    if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes"));
    }

    for mut device_obj in try!(hid_manager.find_keys()) {
        try!(u2fhid::init_device(&mut device_obj));
        try!(u2fhid::ping_device(&mut device_obj));

        match u2fhid::u2f_version(&mut device_obj) {
            Ok(v) => {
                if v != ffi::CString::new("U2F_V2").unwrap() {
                    continue;
                }
                println!("Version OK {:?}", v);

            }
            Err(_) => continue,
        }

        match u2fhid::u2f_register(&mut device_obj, timeout_sec, &challenge, &application) {
            Ok(v) => return Ok(v),
            Err(_) => continue,
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "No security keys responded"))
}

fn u2f_sign(hid_manager: &u2fhid::platform::U2FManager, timeout_sec: u8, challenge: &Vec<u8>, application: &Vec<u8>, key_handle: &Vec<u8>) -> io::Result<Vec<u8>>
{
    if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes"));
    }

    for mut device_obj in try!(hid_manager.find_keys()) {
        try!(u2fhid::init_device(&mut device_obj));
        try!(u2fhid::ping_device(&mut device_obj));

        match u2fhid::u2f_version(&mut device_obj) {
            Ok(v) => {
                if v != ffi::CString::new("U2F_V2").unwrap() {
                    continue;
                }
                println!("Version OK {:?}", v);

            }
            Err(_) => continue,
        }

        match u2fhid::u2f_sign(&mut device_obj, timeout_sec, challenge, application, &key_handle) {
            Ok(v) => return Ok(v),
            Err(_) => continue,
        };
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "No security keys responded"))
}

fn main() {
    println!("Searching for keys...");

    let hid_manager = match u2fhid::platform::open_u2f_hid_manager() {
        Ok(v) => v,
        Err(e) => panic!("Error {:?}", e),
    };

    let signature_result = register_and_sign(&hid_manager).unwrap();
    println!("Signature Result: {}", base64::encode(&signature_result));

    hid_manager.close();
    println!("Done.");
}
