#[cfg(any(target_os = "macos"))]
fn main() {
    println!("cargo:rustc-link-lib=framework=IOKit");
}
