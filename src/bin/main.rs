#[macro_use]
extern crate clap;
use clap::App;
extern crate u2fhid;
use u2fhid::U2FDevice;
use std::ffi::CString;


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

        let challenge = vec![0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1];
        let application = vec![0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1];

        println!("Register: challenge={:?} application={:?}", challenge, application);

        match u2fhid::u2f_register(&mut device_obj, &challenge, &application) {
            Ok(v) => println!("Register Response: {:?}", v),
            Err(e) => panic!("Error! {:?}", e),
        }

    }

    hid_manager.close();
    println!("Done.");
}
