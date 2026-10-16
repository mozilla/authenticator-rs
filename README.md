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

## Native biometric authentication (opt-in)

The non-default `local-biometric` feature supports native applications that use
`hmac-secret` to unlock local encrypted material and require built-in biometric
verification rather than an authenticator PIN. It does not implement operating
system login, store fingerprint templates on the host, or manage application retry
state. Existing builds do not enable this feature.

Enabling the feature alone does not select biometric-only authentication. For a
`SignArgs` already configured with the application's RP ID, credential allow list,
and `hmac-secret` inputs, explicitly select the policy:

```rust,ignore
args.internal_uv_only = true;
args.user_verification_req = UserVerificationRequirement::Required;
args.pin = None;
args.use_ctap1_fallback = false;
args.extensions.local_uv_attempt_limit = Some(3);
```

The same policy is available on `RegisterArgs`. Eligible devices must advertise
configured built-in UV, `hmac-secret`, and biometric enrollment support. PIN
substitution and weaker UV requirements are rejected. CTAP 2.0 and 2.1 reported
UV failures are bounded by the supplied remaining budget (one to three, default
three); zero rejects the operation. Firmware may lock earlier or hide multiple
physical scans behind one response. Applications must persist their own retry
budget and validate the returned credential, signature, RP ID, challenge and
UV/UP flags before using the secret.

On Linux, `local_biometric_devices()` performs capability discovery without
requesting user presence or UV. The feature also exposes
`local_biometric_transport` for selected-device enrollment using the existing
biometric and PIN-management helpers. `extensions.local_device_path` selects a
current hidraw path; it is not proof of device identity, and callers must verify
credential ownership before modifying an existing enrollment. Selected local
operations use bounded HID reads; ordinary operations retain the upstream timeout.
A management-only `extensions.local_pin_only` assertion can prove credential
ownership with an explicitly supplied PIN, but cannot request HMAC/PRF output or
be combined with `internal_uv_only`. These local controls are not serialized.

With the feature enabled, HMAC/PRF outputs, PINs, shared secrets and PIN/UV tokens
are wiped on drop; secret Debug implementations redact their contents. Internal
temporary buffers are also wiped, including OpenSSL error paths. Protocol-required
`Clone` implementations remain available and each clone wipes its own allocation.
Public PIN helper methods retain their `Vec<u8>` return types; internal callers
wrap their results in zeroizing buffers. External callers remain responsible for
those raw helper results. Extract fields from drop-protected PRF outputs by
borrowing or taking rather than moving them directly. Without the feature, the
original traits, Debug output, serialization and authentication policy are retained.

This is best-effort secret lifetime reduction, not memory locking or protection
against privileged live-memory inspection. Applications remain responsible for
securing their own buffers and any copies made outside this crate. Hardware and
firmware behavior require physical-device validation.

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
