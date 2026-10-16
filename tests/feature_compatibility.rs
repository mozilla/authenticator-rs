/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use authenticator::authenticatorservice::{RegisterArgs, SignArgs};
#[cfg(feature = "local-biometric")]
use authenticator::ctap2::server::AuthenticationExtensionsClientInputs;
use authenticator::ctap2::server::{
    HMACGetSecretOutput, PublicKeyCredentialUserEntity, RelyingParty, ResidentKeyRequirement,
    UserVerificationRequirement,
};
use authenticator::Pin;

#[test]
fn existing_argument_literals_and_serialization_remain_compatible() {
    let register = RegisterArgs {
        client_data_hash: [0; 32],
        relying_party: RelyingParty::from("login.example.org"),
        origin: "https://login.example.org".into(),
        user: PublicKeyCredentialUserEntity {
            id: vec![1],
            name: None,
            display_name: None,
        },
        pub_cred_params: vec![],
        exclude_list: vec![],
        user_verification_req: UserVerificationRequirement::Required,
        resident_key_req: ResidentKeyRequirement::Discouraged,
        extensions: Default::default(),
        pin: None,
        use_ctap1_fallback: false,
        #[cfg(feature = "local-biometric")]
        internal_uv_only: false,
    };
    let sign = SignArgs {
        client_data_hash: [0; 32],
        origin: "https://login.example.org".into(),
        relying_party_id: "login.example.org".into(),
        allow_list: vec![],
        user_verification_req: UserVerificationRequirement::Required,
        user_presence_req: true,
        extensions: Default::default(),
        pin: None,
        use_ctap1_fallback: false,
        #[cfg(feature = "local-biometric")]
        internal_uv_only: false,
    };
    for value in [
        serde_json::to_value(register).unwrap(),
        serde_json::to_value(sign).unwrap(),
    ] {
        assert!(value.get("internal_uv_only").is_none());
        let extensions = value["extensions"].as_object().unwrap();
        assert!(extensions.keys().all(|key| !key.starts_with("local_")));
    }
}

#[test]
fn output_clone_remains_available_with_either_feature_state() {
    let output = HMACGetSecretOutput {
        output1: [7; 32],
        output2: Some([8; 32]),
    };
    assert_eq!(output.clone(), output);
    #[cfg(feature = "local-biometric")]
    assert_eq!(format!("{output:?}"), "HMACGetSecretOutput(REDACTED)");
    #[cfg(not(feature = "local-biometric"))]
    assert!(format!("{output:?}").contains("output1: [7, 7"));
}

#[test]
fn pin_padding_and_hash_values_are_unchanged() {
    let pin = Pin::new("123456");
    let padded = pin.padded();
    assert_eq!(&padded[..6], b"123456");
    assert_eq!(padded.len(), 64);
    assert!(padded[6..].iter().all(|byte| *byte == 0));
    let hash = pin.for_pin_token();
    assert_eq!(
        &hash[..],
        &[141, 150, 158, 239, 110, 202, 211, 194, 154, 58, 98, 146, 128, 230, 134, 207]
    );
    {
        let _: Vec<u8> = padded;
        let _: Vec<u8> = hash;
    }
}

#[cfg(feature = "local-biometric")]
#[test]
fn local_policy_fields_are_never_serialized() {
    let inputs = AuthenticationExtensionsClientInputs {
        local_device_path: Some("/dev/hidraw-sensitive-path".into()),
        local_pin_only: true,
        local_uv_attempt_limit: Some(1),
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_value(inputs).unwrap(),
        serde_json::to_value(AuthenticationExtensionsClientInputs::default()).unwrap()
    );
}
