#[macro_use]
extern crate crypto;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
extern crate base64;
extern crate u2fhid;
use std::{io, thread, time};
use std::sync::mpsc::{channel, Sender, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};

const PARAMETER_SIZE : usize = 32;

pub struct WorkUnit
{
    timeout_sec: u8,
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
        let mut security_keys = Vec::new();

        let platform = match u2fhid::platform::open_platform_manager() {
            Ok(v) => v,
            Err(e) => panic!("Failure to open platform HID support: {}", e),
        };

        for mut device_obj in platform.find_keys().unwrap() {
            println!("Device seen {}", device_obj);
            if let Err(_) = u2fhid::init_device(&mut device_obj) {
                continue
            }
            println!("Device inited {}", device_obj);
            if let Err(_) = u2fhid::ping_device(&mut device_obj) {
                continue
            }
            println!("Device pinged {}", device_obj);
            if let Err(_) = u2fhid::u2f_version_is_v2(&mut device_obj){
                continue
            }
            println!("Device initialized {}", device_obj);
            security_keys.push(device_obj);
        }

        loop {
            println!("Doing work!");
            let work = match work_rx.recv() {
                Ok(v) => v,
                Err(e) => panic!("Receiver failed {}", e),
            };

            work.result_tx.send(Ok(Vec::new()));
        }

        // let mut iteration_count = 0;
        // while iteration_count < timeout_sec {
        //     if let Ok(ref mut list) = devices.lock() {
        //         // This indexing is because I don't know how to use .iter() and
        //         // keep the U2FDevice traits
        //         for idx in 0..list.len() {
        //             println!("Register {}", list[idx]);
        //             match u2fhid::u2f_register(&mut list[idx], challenge, application) {
        //                 Ok(v) => {
        //                     println!("Register OK {:?}", v);
        //                     // First to complete, we return
        //                     // TODO: Cancel the others?
        //                     for cancel_idx in 0..list.len() {
        //                         if cancel_idx == idx {
        //                             continue;
        //                         }
        //                         let _ = u2fhid::u2f_cancel(&mut list[cancel_idx]);
        //                     }
        //                     return Ok(v)
        //                 },
        //                 Err(_) => continue,
        //             }
        //         }
        //     }

        //     // We've tried all attached security keys
        //     iteration_count += 1;
        //     thread::sleep(time::Duration::from_secs(1));
        // }

        // if let Ok(ref mut list) = devices.lock() {
        //     for cancel_idx in 0..list.len() {
        //         let _ = u2fhid::u2f_cancel(&mut list[cancel_idx]);
        //     }
        // }

        // Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out"))
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
            timeout_sec: timeout_sec,
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

    fn sign_thread(platform: &u2fhid::platform::PlatformManager, timeout_sec: u8,
                       challenge: &Vec<u8>, application: &Vec<u8>, key_handle: &Vec<u8>) -> io::Result<Vec<u8>>
    {
        let device_mutex: Arc<Mutex<Vec<u2fhid::platform::Device>>> = Arc::new(Mutex::new(Vec::new()));
        let devices = device_mutex.clone();

        if let Ok(ref mut list) = devices.lock() {
            for mut device_obj in try!(platform.find_keys()) {
                if let Err(_) = u2fhid::init_device(&mut device_obj) {
                    continue
                }
                if let Err(_) = u2fhid::ping_device(&mut device_obj) {
                    continue
                }
                if let Err(_) = u2fhid::u2f_version_is_v2(&mut device_obj){
                    continue
                }
                list.push(device_obj);
            }
        }

        let mut iteration_count = 0;
        while iteration_count < timeout_sec {
            if let Ok(ref mut list) = devices.lock() {
                // This indexing is because I don't know how to use .iter() and
                // keep the U2FDevice traits
                for idx in 0..list.len() {
                    match u2fhid::u2f_sign(&mut list[idx], challenge, application, key_handle) {
                        Ok(v) => {
                            // First to complete, we return
                            // TODO: Cancel the others?
                            for cancel_idx in 0..list.len() {
                                if cancel_idx == idx {
                                    continue;
                                }
                                let _ = u2fhid::u2f_cancel(&mut list[cancel_idx]);
                            }
                            return Ok(v)
                        },
                        Err(_) => continue,
                    }
                }
            }

            // We've tried all attached security keys
            iteration_count += 1;
            thread::sleep(time::Duration::from_secs(1));
        }

        if let Ok(ref mut list) = devices.lock() {
            for cancel_idx in 0..list.len() {
                let _ = u2fhid::u2f_cancel(&mut list[cancel_idx]);
            }
        }

        Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out"))
    }

    pub fn sign<F>(&self, timeout_sec: u8, challenge: Vec<u8>, application: Vec<u8>, key_handle: Vec<u8>, callback: F)
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
            callback(Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes")));
            return;
        }

        if let Err(e) = thread::Builder::new().spawn(move || {
            let platform = match u2fhid::platform::open_platform_manager() {
                Ok(v) => v,
                Err(e) => panic!("Failure to open platform HID support: {}", e),
            };

            let result = U2FManager::sign_thread(&platform, timeout_sec, &challenge, &application, &key_handle);
            platform.close();
            callback(result);
        }) {
            panic!("Failed to spawn thread: {}", e);
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
