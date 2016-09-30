#[macro_use]
extern crate clap;
use clap::{App};

extern crate u2fhid;

fn main() {
    u2fhid::platform::find_keys();
}
