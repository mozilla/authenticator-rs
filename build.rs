fn main() {
    #[cfg(any(target_os = "macos"))]
    println!("cargo:rustc-link-lib=framework=IOKit");
}
