# A Rust USB HID library for interacting with U2F Security Keys

[![Build Status](https://travis-ci.org/jcjones/u2f-hid-rs.svg?branch=master)](https://travis-ci.org/jcjones/u2f-hid-rs)
![Maturity Level](https://img.shields.io/badge/maturity-beta-yellow.svg)

This is a cross-platform library for interacting with U2F Security Key devices via Rust. Supports Windows, Linux, and OSX.

## Usage

There's only a simple example function that tries to register and sign right now. It uses
[env_logger](http://rust-lang-nursery.github.io/log/env_logger/) for logging, which you
configure with the `RUST_LOG` environment variable:

```
cargo build
RUST_LOG=debug cargo run --example main
```

Proper usage should be to call into this library from something else - e.g., Firefox. There are
some [C headers exposed for the purpose](u2f-hid-rs/blob/master/src/u2fhid-capi.h).

## Fuzzing

To fuzz, you will need cargo-fuzz (the latest version from GitHub) as well as Rust Nightly.

```
rustup install nightly
cargo install --git https://github.com/rust-fuzz/cargo-fuzz/

rustup run nightly cargo fuzz run u2f_read -- -max_len=512
rustup run nightly cargo fuzz run u2f_read_write -- -max_len=512
```
