# Contributing to authenticator-rs

Thanks for your interest in contributing to `authenticator-rs`.

## Where to report bugs

`authenticator-rs` is *used* by Firefox, but it is one component of 
[Firefox's WebAuthn stack][ffx-webauthn], which isn't used on all platforms or
in all circumstances. GitHub issues are *only* for this library.

All synchronised passkey manager browser extensions *completely replace*
Firefox's WebAuthn APIs. Report any bugs when using these to their creators,
even if they're set to fall back to Firefox's API.

You can report WebAuthn bugs in Mozilla's official Firefox builds via Bugzilla:

* Android: [Firefox for Android → WebAuthn][bz-android]
* Other platforms: [Core → DOM: Web Authentication][bz-webauthn]

Third-party builds of Firefox (including those from Linux distributions) may
modify Firefox in ways outside of Mozilla's control, and may not have access to
restricted WebAuthn entitlements for their builds (needed on Android, iOS and
macOS). Issues with these builds should be reported to their maintainers.

[bz-android]: https://bugzilla.mozilla.org/buglist.cgi?product=Firefox%20for%20Android&component=WebAuthn&bug_status=__open__
[bz-webauthn]: https://bugzilla.mozilla.org/buglist.cgi?product=Core&component=DOM%3A%20Web%20Authentication&bug_status=__open__
[ffx-webauthn]: https://searchfox.org/firefox-main/source/dom/webauthn

## Where to send patches

**`authenticator-rs` has two repositories:**

* In Firefox's source tree: [`/dom/webauthn/authenticator`](https://searchfox.org/firefox-main/source/dom/webauthn/authenticator)
* On GitHub: https://github.com/mozilla/authenticator-rs/

As the library is primarily intended for use in Firefox, we *strongly* prefer
making changes in Firefox first. We periodically synchronise changes back to
GitHub (as a manual process).

The version of the library used in Firefox uses a rolling release, and
*might not* have discrete version number of its own.

There are some small differences between these versions, and that affects which
version to send patches for. Both versions have:

* Rust unit tests (in Firefox, use [`./mach rusttests`][rusttests]), run in CI
* NSS support
* Same platform support

### Firefox version

***Generally speaking, most changes should be made in Firefox first.***

Check out Firefox's [getting set up][build-firefox] and
[how to submit a patch][patch-firefox] guides for more information.

Firefox uses `authenticator-rs` as its WebAuthn backend on:

* BSD
* Linux
* [WebDriver virtual authenticator][virtual] (all platforms)

It is used as a fallback when platform APIs are not available on:

* macOS ([locally-signed and unsigned builds][macos-signing], and old versions)
* Windows (before Windows 10 version 1903)

Pros:

* Very easy to test changes in Firefox
* API changes can be made in lock-step with Firefox
* Better test coverage from [Firefox][mochitest] and [WPT][] test suites, runnable locally and in [Try][] (CI)
* Firefox's linting rules applied in CI

Cons:

* Cold builds of Firefox are slow (can't use Artifact Mode)
* Higher resource requirements (CPU, RAM, disk), especially with `rust-analyzer`
* Only supports NSS, so crypto changes need to be replicated
* No [standalone CLI examples](./examples) and [fuzz tests](./fuzz/)

### GitHub version

Generally speaking, changes to [cryptography-related code](./src/crypto/) and
[examples](./examples/) are the only things that should be submitted to GitHub
first.

Pros:

* Faster builds
* Lower resource requirements (CPU, RAM, disk)
* Supports multiple crypto backends (NSS, OpenSSL, RustCrypto), all tested in GitHub Actions
* [Standalone CLI examples](./examples) and [fuzz tests](./fuzz)

Cons:

* Difficult to test changes in Firefox
* Difficult to integrate changes back into Firefox
* Limited test coverage
* Firefox's linters not available in GitHub Actions

[build-firefox]: https://firefox-source-docs.mozilla.org/setup/index.html
[macos-signing]: https://firefox-source-docs.mozilla.org/contributing/signing/signing_macos_build.html
[mochitest]: https://firefox-source-docs.mozilla.org/testing/mochitest-plain/index.html
[patch-firefox]: https://firefox-source-docs.mozilla.org/contributing/how_to_submit_a_patch.html
[rusttests]: https://firefox-source-docs.mozilla.org/testing-rust-code/index.html
[Try]: https://firefox-source-docs.mozilla.org/taskcluster/try.html
[virtual]: https://www.w3.org/TR/webauthn-3/#sctn-automation-virtual-authenticators
[wpt]: https://firefox-source-docs.mozilla.org/web-platform/index.html
