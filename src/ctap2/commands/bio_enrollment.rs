use crate::{
    crypto::{PinUvAuthParam, PinUvAuthToken},
    ctap2::server::UserVerificationRequirement,
    errors::AuthenticatorError,
    transport::errors::HIDError,
    FidoDevice, Pin,
};
use serde::{
    de::{Error as SerdeError, IgnoredAny, MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_bytes::ByteBuf;
use serde_cbor::{from_slice, to_vec, Value};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::fmt;

use super::{Command, CommandError, PinUvAuthCommand, Request, RequestCtap2, StatusCode};

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum BioEnrollmentModality {
    Fingerprint = 0x01,
}

pub type BioTemplateId = Vec<u8>;
#[derive(Debug, Clone, Deserialize, Default)]
struct BioEnrollmentParams {
    template_id: Option<ByteBuf>,           // Template Identifier.
    template_friendly_name: Option<String>, // Template Friendly Name.
    timeout_milliseconds: Option<u64>,      // Timeout in milliSeconds.
}

impl BioEnrollmentParams {
    fn has_some(&self) -> bool {
        self.template_id.is_some()
            || self.template_friendly_name.is_some()
            || self.timeout_milliseconds.is_some()
    }
}

impl Serialize for BioEnrollmentParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map_len = 0;
        if self.template_id.is_some() {
            map_len += 1;
        }
        if self.template_friendly_name.is_some() {
            map_len += 1;
        }
        if self.timeout_milliseconds.is_some() {
            map_len += 1;
        }

        let mut map = serializer.serialize_map(Some(map_len))?;
        if let Some(template_id) = &self.template_id {
            map.serialize_entry(&0x01, &ByteBuf::from(template_id.as_slice()))?;
        }
        if let Some(template_friendly_name) = &self.template_friendly_name {
            map.serialize_entry(&0x02, template_friendly_name)?;
        }
        if let Some(timeout_milliseconds) = &self.timeout_milliseconds {
            map.serialize_entry(&0x03, timeout_milliseconds)?;
        }
        map.end()
    }
}

#[derive(Debug)]
pub enum BioEnrollmentCommand {
    EnrollBegin(u64),
    EnrollCaptureNextSample((ByteBuf, u64)),
    CancelCurrentEnrollment,
    EnumerateEnrollments,
    SetFriendlyName((BioTemplateId, String)),
    RemoveEnrollment(BioTemplateId),
    GetFingerprintSensorInfo,
}

impl BioEnrollmentCommand {
    fn to_id_and_param(&self) -> (u8, BioEnrollmentParams) {
        let mut params = BioEnrollmentParams::default();
        match &self {
            BioEnrollmentCommand::EnrollBegin(timeout) => {
                params.timeout_milliseconds = Some(*timeout);
                (0x01, params)
            }
            BioEnrollmentCommand::EnrollCaptureNextSample((id, timeout)) => {
                params.template_id = Some(id.clone());
                params.timeout_milliseconds = Some(*timeout);
                (0x02, params)
            }
            BioEnrollmentCommand::CancelCurrentEnrollment => (0x03, params),
            BioEnrollmentCommand::EnumerateEnrollments => (0x04, params),
            BioEnrollmentCommand::SetFriendlyName((id, name)) => {
                params.template_id = Some(ByteBuf::from(id.as_slice()));
                params.template_friendly_name = Some(name.clone());
                (0x05, params)
            }
            BioEnrollmentCommand::RemoveEnrollment(id) => {
                params.template_id = Some(ByteBuf::from(id.as_slice()));
                (0x06, params)
            }
            BioEnrollmentCommand::GetFingerprintSensorInfo => (0x07, params),
        }
    }
}

#[derive(Debug)]
pub struct BioEnrollment {
    /// The user verification modality being requested
    pub modality: BioEnrollmentModality,
    /// The authenticator user verification sub command currently being requested
    pub(crate) subcommand: BioEnrollmentCommand,
    /// First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken.
    pin_uv_auth_param: Option<PinUvAuthParam>,
    pin_uv_auth_token: Option<PinUvAuthToken>,
    /// Get the user verification type modality. This MUST be set to true.
    get_modality: Option<bool>,
    pin: Option<Pin>,
    use_legacy_preview: bool,
}

impl BioEnrollment {
    pub(crate) fn new(subcommand: BioEnrollmentCommand, use_legacy_preview: bool) -> Self {
        Self {
            modality: BioEnrollmentModality::Fingerprint, // As per spec: Currently always "Fingerprint"
            subcommand,
            pin_uv_auth_param: None,
            pin_uv_auth_token: None,
            pin: None,
            use_legacy_preview,
            get_modality: None, // Currently not used
        }
    }

    pub(crate) fn regenerate_puap(&mut self) -> Result<(), AuthenticatorError> {
        let token = self.pin_uv_auth_token.take();
        self.set_pin_uv_auth_param(token)
    }
}

impl Serialize for BioEnrollment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Need to define how many elements are going to be in the map
        // beforehand
        let mut map_len = 2;
        let (id, params) = self.subcommand.to_id_and_param();
        if params.has_some() {
            map_len += 1;
        }
        if self.pin_uv_auth_param.is_some() {
            map_len += 2;
        }

        let mut map = serializer.serialize_map(Some(map_len))?;

        map.serialize_entry(&0x01, &self.modality)?; // Per spec currently always Fingerprint
        map.serialize_entry(&0x02, &id)?;
        if params.has_some() {
            map.serialize_entry(&0x03, &params)?;
        }

        if let Some(ref pin_uv_auth_param) = self.pin_uv_auth_param {
            map.serialize_entry(&0x04, &pin_uv_auth_param.pin_protocol.id())?;
            map.serialize_entry(&0x05, pin_uv_auth_param)?;
        }

        map.end()
    }
}

impl Request<()> for BioEnrollment {}

impl PinUvAuthCommand for BioEnrollment {
    fn pin(&self) -> &Option<Pin> {
        &self.pin
    }

    fn set_pin(&mut self, pin: Option<Pin>) {
        self.pin = pin;
    }

    fn get_rp_id(&self) -> Option<&String> {
        None
    }

    fn set_pin_uv_auth_param(
        &mut self,
        pin_uv_auth_token: Option<PinUvAuthToken>,
    ) -> Result<(), AuthenticatorError> {
        let mut param = None;
        if let Some(token) = pin_uv_auth_token {
            // pinUvAuthParam (0x04): the result of calling
            // authenticate(pinUvAuthToken, fingerprint (0x01) || uint8(subCommand) || subCommandParams).
            let (id, params) = self.subcommand.to_id_and_param();
            let modality = self.modality as u8;
            let mut data = vec![modality, id];
            if params.has_some() {
                data.extend(to_vec(&params).map_err(CommandError::Serializing)?);
            }
            param = Some(token.clone().derive(&data).map_err(CommandError::Crypto)?);
            self.pin_uv_auth_token = Some(token);
        }
        self.pin_uv_auth_param = param;
        Ok(())
    }

    fn can_skip_user_verification(
        &mut self,
        _info: &crate::AuthenticatorInfo,
        _uv: UserVerificationRequirement,
    ) -> bool {
        // "discouraged" does not exist for BioEnrollment
        false
    }

    fn set_uv_option(&mut self, _uv: Option<bool>) {
        /* No-op */
    }

    fn get_pin_uv_auth_param(&self) -> Option<&PinUvAuthParam> {
        self.pin_uv_auth_param.as_ref()
    }
}

impl RequestCtap2 for BioEnrollment {
    type Output = BioEnrollmentResponse;

    fn command(&self) -> Command {
        if self.use_legacy_preview {
            Command::BioEnrollmentPreview
        } else {
            Command::BioEnrollment
        }
    }

    fn wire_format(&self) -> Result<Vec<u8>, HIDError> {
        let output = to_vec(&self).map_err(CommandError::Serializing)?;
        trace!("client subcommmand: {:04X?}", &output);
        Ok(output)
    }

    fn handle_response_ctap2<Dev>(
        &self,
        _dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, HIDError>
    where
        Dev: FidoDevice,
    {
        if input.is_empty() {
            return Err(CommandError::InputTooSmall.into());
        }

        let status: StatusCode = input[0].into();
        if status.is_ok() {
            if input.len() > 1 {
                trace!("parsing bio enrollment response data: {:#04X?}", &input);
                let bio_enrollment =
                    from_slice(&input[1..]).map_err(CommandError::Deserializing)?;
                Ok(bio_enrollment)
            } else {
                // Some subcommands return only an OK-status without any data
                Ok(BioEnrollmentResponse::default())
            }
        } else {
            let data: Option<Value> = if input.len() > 1 {
                Some(from_slice(&input[1..]).map_err(CommandError::Deserializing)?)
            } else {
                None
            };
            Err(CommandError::StatusCode(status, data).into())
        }
    }

    fn send_to_virtual_device<Dev: crate::VirtualFidoDevice>(
        &self,
        _dev: &mut Dev,
    ) -> Result<Self::Output, HIDError> {
        unimplemented!()
    }
}

#[derive(Debug, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum LastEnrollmentSampleStatus {
    /// Good fingerprint capture.
    Ctap2EnrollFeedbackFpGood = 0x00,
    /// Fingerprint was too high.
    Ctap2EnrollFeedbackFpTooHigh = 0x01,
    /// Fingerprint was too low.
    Ctap2EnrollFeedbackFpTooLow = 0x02,
    /// Fingerprint was too left.
    Ctap2EnrollFeedbackFpTooLeft = 0x03,
    /// Fingerprint was too right.
    Ctap2EnrollFeedbackFpTooRight = 0x04,
    /// Fingerprint was too fast.
    Ctap2EnrollFeedbackFpTooFast = 0x05,
    /// Fingerprint was too slow.
    Ctap2EnrollFeedbackFpTooSlow = 0x06,
    /// Fingerprint was of poor quality.
    Ctap2EnrollFeedbackFpPoorQuality = 0x07,
    /// Fingerprint was too skewed.
    Ctap2EnrollFeedbackFpTooSkewed = 0x08,
    /// Fingerprint was too short.
    Ctap2EnrollFeedbackFpTooShort = 0x09,
    /// Merge failure of the capture.
    Ctap2EnrollFeedbackFpMergeFailure = 0x0A,
    /// Fingerprint already exists.
    Ctap2EnrollFeedbackFpExists = 0x0B,
    /// (this error number is available)
    Unused = 0x0C,
    /// User did not touch/swipe the authenticator.
    Ctap2EnrollFeedbackNoUserActivity = 0x0D,
    /// User did not lift the finger off the sensor.
    Ctap2EnrollFeedbackNoUserPresenceTransition = 0x0E,
}

#[derive(Debug, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum FingerprintKind {
    TouchSensor = 0x01, // For touch type sensor, its value is 1.
    SwipeSensor = 0x02, // For swipe type sensor its value is 2.
}

#[derive(Debug, Serialize)]
pub(crate) struct BioTemplateInfo {
    template_id: ByteBuf,
    template_friendly_name: Option<String>,
}

impl<'de> Deserialize<'de> for BioTemplateInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BioTemplateInfoResponseVisitor;

        impl<'de> Visitor<'de> for BioTemplateInfoResponseVisitor {
            type Value = BioTemplateInfo;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut template_id = None; // (0x01)
                let mut template_friendly_name = None; // (0x02)
                while let Some(key) = map.next_key()? {
                    match key {
                        0x01 => {
                            if template_id.is_some() {
                                return Err(SerdeError::duplicate_field("template_id"));
                            }
                            template_id = Some(map.next_value()?);
                        }
                        0x02 => {
                            if template_friendly_name.is_some() {
                                return Err(SerdeError::duplicate_field("template_friendly_name"));
                            }
                            template_friendly_name = Some(map.next_value()?);
                        }
                        k => {
                            warn!("BioTemplateInfo: unexpected key: {:?}", k);
                            let _ = map.next_value::<IgnoredAny>()?;
                            continue;
                        }
                    }
                }

                if let Some(template_id) = template_id {
                    Ok(BioTemplateInfo {
                        template_id,
                        template_friendly_name,
                    })
                } else {
                    Err(SerdeError::missing_field("template_id"))
                }
            }
        }
        deserializer.deserialize_bytes(BioTemplateInfoResponseVisitor)
    }
}

#[derive(Default, Debug)]
pub struct BioEnrollmentResponse {
    /// The user verification modality.
    pub(crate) modality: Option<BioEnrollmentModality>,
    /// Indicates the type of fingerprint sensor. For touch type sensor, its value is 1. For swipe type sensor its value is 2.
    pub(crate) fingerprint_kind: Option<FingerprintKind>,
    /// Indicates the maximum good samples required for enrollment.
    pub(crate) max_capture_samples_required_for_enroll: Option<u64>,
    /// Template Identifier.
    pub(crate) template_id: Option<ByteBuf>,
    /// Last enrollment sample status.
    pub(crate) last_enroll_sample_status: Option<LastEnrollmentSampleStatus>,
    /// Number of more sample required for enrollment to complete
    pub(crate) remaining_samples: Option<u64>,
    /// Array of templateInfo’s
    pub(crate) template_infos: Vec<BioTemplateInfo>,
    /// Indicates the maximum number of bytes the authenticator will accept as a templateFriendlyName.
    pub(crate) max_template_friendly_name: Option<u64>,
}

impl<'de> Deserialize<'de> for BioEnrollmentResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BioEnrollmentResponseVisitor;

        impl<'de> Visitor<'de> for BioEnrollmentResponseVisitor {
            type Value = BioEnrollmentResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut modality = None; // (0x01)
                let mut fingerprint_kind = None; // (0x02)
                let mut max_capture_samples_required_for_enroll = None; // (0x03)
                let mut template_id = None; // (0x04)
                let mut last_enroll_sample_status = None; // (0x05)
                let mut remaining_samples = None; // (0x06)
                let mut template_infos = None; // (0x07)
                let mut max_template_friendly_name = None; // (0x08)

                while let Some(key) = map.next_key()? {
                    match key {
                        0x01 => {
                            if modality.is_some() {
                                return Err(SerdeError::duplicate_field("modality"));
                            }
                            modality = Some(map.next_value()?);
                        }
                        0x02 => {
                            if fingerprint_kind.is_some() {
                                return Err(SerdeError::duplicate_field("fingerprint_kind"));
                            }
                            fingerprint_kind = Some(map.next_value()?);
                        }
                        0x03 => {
                            if max_capture_samples_required_for_enroll.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "max_capture_samples_required_for_enroll",
                                ));
                            }
                            max_capture_samples_required_for_enroll = Some(map.next_value()?);
                        }
                        0x04 => {
                            if template_id.is_some() {
                                return Err(SerdeError::duplicate_field("template_id"));
                            }
                            template_id = Some(map.next_value()?);
                        }
                        0x05 => {
                            if last_enroll_sample_status.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "last_enroll_sample_status",
                                ));
                            }
                            last_enroll_sample_status = Some(map.next_value()?);
                        }
                        0x06 => {
                            if remaining_samples.is_some() {
                                return Err(SerdeError::duplicate_field("remaining_samples"));
                            }
                            remaining_samples = Some(map.next_value()?);
                        }
                        0x07 => {
                            if template_infos.is_some() {
                                return Err(SerdeError::duplicate_field("template_infos"));
                            }
                            template_infos = Some(map.next_value()?);
                        }
                        0x08 => {
                            if max_template_friendly_name.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "max_template_friendly_name",
                                ));
                            }
                            max_template_friendly_name = Some(map.next_value()?);
                        }
                        k => {
                            warn!("BioEnrollmentResponse: unexpected key: {:?}", k);
                            let _ = map.next_value::<IgnoredAny>()?;
                            continue;
                        }
                    }
                }

                Ok(BioEnrollmentResponse {
                    modality,
                    fingerprint_kind,
                    max_capture_samples_required_for_enroll,
                    template_id,
                    last_enroll_sample_status,
                    remaining_samples,
                    template_infos: template_infos.unwrap_or_default(),
                    max_template_friendly_name,
                })
            }
        }
        deserializer.deserialize_bytes(BioEnrollmentResponseVisitor)
    }
}

#[derive(Debug, Serialize)]
pub struct EnrollmentInfo {
    template_id: Vec<u8>,
    template_friendly_name: Option<String>,
}

impl From<&BioTemplateInfo> for EnrollmentInfo {
    fn from(value: &BioTemplateInfo) -> Self {
        Self {
            template_id: value.template_id.to_vec(),
            template_friendly_name: value.template_friendly_name.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub enum BioEnrollmentResult {
    EnrollmentList(Vec<EnrollmentInfo>),
    DeleteSucess,
    UpdateSuccess,
}
