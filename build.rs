extern crate bindgen;

use std::env;
use std::path::PathBuf;

#[cfg(not(target_os = "linux"))]
fn main () {}

#[cfg(target_os = "linux")]
fn main() {
    let bindings = bindgen::Builder::default()
        .header("src/linux/hidwrapper.h")
        .whitelist_var("_HIDIOCGRDESCSIZE")
        .whitelist_var("_HIDIOCGRDESC")
        .generate()
        .expect("Unable to get hidraw bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write hidraw bindings");
}
