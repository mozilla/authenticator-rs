#[macro_use]
extern crate crypto;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
extern crate clap;
use clap::App;
extern crate u2fhid;
use u2fhid::U2FDevice;
use std::ffi::CString;
extern crate base64;

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

        println!("Register: challenge={:?} application={:?}", challenge.result_str(), application.result_str());

        match u2fhid::u2f_register(&mut device_obj, 15, &chall_bytes, &app_bytes) {
            Ok(v) => println!("Register Response: {:?}", base64::encode(&v)),
            Err(e) => panic!("Error! {:?}", e),
        }

    }

    hid_manager.close();
    println!("Done.");
}
