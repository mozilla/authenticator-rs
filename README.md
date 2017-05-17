# A Rust USB HID library for interacting with U2F Security Keys

[![Build Status](https://travis-ci.org/jcjones/u2f-hid-rs.svg?branch=master)](https://travis-ci.org/jcjones/u2f-hid-rs)

This is a cross-platform library for interacting with U2F Security Key devices via Rust.

## Usage

There's only a simple main function that tries to register and sign right now. It uses
[env_logger](http://rust-lang-nursery.github.io/log/env_logger/) for logging, which you
configure with the `RUST_LOG` environment variable:

```
cargo build
RUST_LOG=debug ./target/debug/main
```