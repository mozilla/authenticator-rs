#[cfg(any(target_os = "linux"))]
#[macro_use]
extern crate nix;
#[cfg(any(target_os = "linux"))]
#[macro_use]
extern crate libc;
#[cfg(any(target_os = "linux"))]
extern crate libudev;

#[cfg(any(target_os = "linux"))]
#[path="linux/mod.rs"]
pub mod platform;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
