#[macro_use]
extern crate crypto;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
extern crate clap;
use clap::App;
extern crate u2fhid;
use u2fhid::U2FDevice;
use std::io::{Read, Write};
use std::ffi::CString;
extern crate base64;

fn perform_sign<T>(dev: &mut T, timeout_sec: u8, challenge: &Vec<u8>, application: &Vec<u8>, register_response: &Vec<u8>)
    where T: U2FDevice + Read + Write
{
    println!("Register Response: {}", base64::encode(register_response));
    println!("Sign: challenge={} application={}", base64::encode(challenge), base64::encode(application));

    if register_response[0] != 0x05 {
        panic!("Reserved byte not set correctly");
    }

    let key_handle_len = register_response[66] as usize;
    let mut public_key = register_response.clone();
    let mut key_handle = public_key.split_off(67);
    let attestation = key_handle.split_off(key_handle_len);

    println!("Key Handle ({}): {}", key_handle.len(), base64::encode(&key_handle));
    println!("Attestation ({}): {}", attestation.len(), base64::encode(&attestation));

    match u2fhid::u2f_sign(dev, 15, challenge, application, &key_handle) {
        Ok(v) => println!("Sign Response: {}", base64::encode(&v)),
        Err(e) => panic!("Sign Error! {:?}", e),
    }
}

fn main() {
    println!("Searching for keys...");

    let hid_manager = match u2fhid::platform::open_u2f_hid_manager() {
        Ok(v) => v,
        Err(e) => panic!("Error {:?}", e),
    };

    let keys = hid_manager.find_keys();
    let keys = match keys {
        Ok(v) => v,
        Err(e) => panic!("Error! {:?}", e),
    };

    println!("Resulting keys:");
    for mut device_obj in keys {
        println!("key found: {}", device_obj);

        if let Err(e) = u2fhid::init_device(&mut device_obj) {
            panic!("Error! {:?}", e);
        }

        u2fhid::ping_device(&mut device_obj);
        println!("Init completed for {}", device_obj);

        match u2fhid::u2f_version(&mut device_obj) {
            Ok(v) => {
                if v != CString::new("U2F_V2").unwrap() {
                    continue;
                }
                println!("Version OK {:?}", v);

            }
            Err(e) => continue,
        }

        let mut challenge = Sha256::new();
        challenge.input_str(r#"{"challenge": "1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70", "version": "U2F_V2", "appId": "http://demo.yubico.com"}"#);
        let mut chall_bytes: Vec<u8> = vec![0; challenge.output_bytes()];
        challenge.result(&mut chall_bytes);

        let mut application = Sha256::new();
        application.input_str("http://demo.yubico.com");
        let mut app_bytes: Vec<u8> = vec![0; application.output_bytes()];
        application.result(&mut app_bytes);

        println!("Register: challenge={} application={}", base64::encode(&chall_bytes), base64::encode(&app_bytes));

        // let mycha = base64::decode_config("YehxSWLRsjJPNHfVYUyQVYdcgWfneCoIbMYT9bSG+2w=", base64::STANDARD).unwrap();
        // let myapp = base64::decode_config("GYVvKtSGqVVCD6mI/lgoQvQH9Mo0kjkYJriaknyiPHA=", base64::STANDARD).unwrap();
        // let mykey = base64::decode_config("mWAcNPL7sqL6dBLW1gROaKeAgfd_abovDpNad9XtmVbp8XOHqXw9MsTEn3cz3RFjBr0HCyxPEznVtJ_nGdVvCw", base64::URL_SAFE_NO_PAD).unwrap();

        // println!("SIGN: challenge={} application={} kh={}", base64::encode(&mycha), base64::encode(&myapp), base64::encode(&mykey));
        // perform_sign(&mut device_obj, 15, &mycha, &myapp, &mykey);

        // match u2fhid::u2f_sign(&mut device_obj, 15, &chall_bytes, &app_bytes, &mykey) {
        //     Ok(v) => println!("Sign Response: {}", base64::encode(&v)),
        //     Err(e) => panic!("Sign Error! {:?}", e),
        // }

        match u2fhid::u2f_register(&mut device_obj, 15, &chall_bytes, &app_bytes) {
            Ok(response) => perform_sign(&mut device_obj, 15, &chall_bytes, &app_bytes, &response),
            Err(e) => panic!("Register Error! {:?}", e),
        }


    }

    hid_manager.close();
    println!("Done.");
}
