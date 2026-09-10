# A Rust library for interacting with CTAP1/CTAP2 Security Keys

[![Build and test](https://github.com/mozilla/authenticator-rs/actions/workflows/ci.yml/badge.svg?branch=ctap2-2021)](https://github.com/mozilla/authenticator-rs/actions/workflows/ci.yml)
![Maturity Level](https://img.shields.io/badge/maturity-release-green.svg)

This is a cross-platform library for directly interacting with Security Key-type devices via Rust.

- **Supported Platforms**: FreeBSD, Linux, macOS[^1], NetBSD, OpenBSD, and Windows[^2].
- **Supported Transports**: USB HID.
- **Supported Protocols**: [FIDO CTAP1 (U2F)][u2f], [CTAP 2.0][], CTAP 2.1-PRE, [CTAP 2.1][].

This library is primarily intended [for use by Firefox][ffx] on platforms that
_do not_ provide WebAuthn APIs (as there are on Android, iOS, [macOS][] and
[Windows][hello]). It implements a subset of the CTAP protocol that is useful
for a web browser.

This library currently focuses on USB security keys, but is expected to be extended to
support additional transports.

[^1]: [macOS has its own platform WebAuthn API][macOS] (which also supports iCloud Keychain), but still allows direct, transport level communication with authenticators.

[^2]: Windows 10 v1903 and later block direct, transport level access to authenticators to applications _not_ running as Administrator, breaking this library for most applications. [Applications will need to use the platform APIs instead][hello].

## Usage

Proper usage should be to call into this library from something else - e.g., Firefox.

[The `ctap2` example](./examples/ctap2.rs) will register and sign a non-discoverable credential
with a USB CTAP1 or CTAP2 authenticator, in a similar manner to a web browser that supports the
WebAuthn API:

```sh
cargo build --example ctap2
RUST_LOG=debug cargo run --example ctap2
```

There are more examples in [the `examples` directory](./examples/).

[The `RUST_LOG` environment variable controls logging](http://rust-lang-nursery.github.io/log/env_logger/).

## Tests

There are some tests of the cross-platform runloop logic and the protocol decoder:

```sh
cargo test
```

## Fuzzing

There are fuzzers for the USB protocol reader, basically fuzzing inputs from the HID layer.
There are not (yet) fuzzers for the C API used by callers (such as Gecko).

To fuzz, you will need cargo-fuzz (the latest version from GitHub) as well as Rust Nightly.

```sh
rustup install nightly
cargo install cargo-fuzz

cargo +nightly fuzz run u2f_read -- -max_len=512
cargo +nightly fuzz run u2f_read_write -- -max_len=512
```

[CTAP 2.0]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html
[CTAP 2.1]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html
[ffx]: https://searchfox.org/firefox-main/source/dom/webauthn
[hello]: https://github.com/microsoft/webauthn
[macOS]: https://developer.apple.com/documentation/authenticationservices/public-private-key-authentication
[u2f]: https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-raw-message-formats-v1.1-id-20160915.html
