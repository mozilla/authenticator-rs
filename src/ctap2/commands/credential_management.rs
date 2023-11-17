use super::{Command, CommandError, CtapResponse, PinUvAuthCommand, RequestCtap2, StatusCode};
use crate::{
    crypto::{COSEKey, PinUvAuthParam, PinUvAuthToken},
    ctap2::server::{
        PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity, RelyingParty, RpIdHash,
        UserVerificationRequirement,
    },
    errors::AuthenticatorError,
    transport::errors::HIDError,
    FidoDevice,
};
use serde::{
    de::{Error as SerdeError, IgnoredAny, MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_bytes::ByteBuf;
use serde_cbor::{de::from_slice, to_vec, Value};
use std::fmt;

#[derive(Debug, Clone, Deserialize, Default)]
struct CredManagementParams {
    rp_id_hash: Option<RpIdHash>, // RP ID SHA-256 hash
    credential_id: Option<PublicKeyCredentialDescriptor>, // Credential Identifier
    user: Option<PublicKeyCredentialUserEntity>, // User Entity
}

impl CredManagementParams {
    fn has_some(&self) -> bool {
        self.rp_id_hash.is_some() || self.credential_id.is_some() || self.user.is_some()
    }
}

impl Serialize for CredManagementParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map_len = 0;
        if self.rp_id_hash.is_some() {
            map_len += 1;
        }
        if self.credential_id.is_some() {
            map_len += 1;
        }
        if self.user.is_some() {
            map_len += 1;
        }

        let mut map = serializer.serialize_map(Some(map_len))?;
        if let Some(rp_id_hash) = &self.rp_id_hash {
            map.serialize_entry(&0x01, &ByteBuf::from(rp_id_hash.as_ref()))?;
        }
        if let Some(credential_id) = &self.credential_id {
            map.serialize_entry(&0x02, credential_id)?;
        }
        if let Some(user) = &self.user {
            map.serialize_entry(&0x03, user)?;
        }
        map.end()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) enum CredManagementCommand {
    GetCredsMetadata,
    EnumerateRPsBegin,
    EnumerateRPsGetNextRP,
    EnumerateCredentialsBegin(RpIdHash),
    EnumerateCredentialsGetNextCredential,
    DeleteCredential(PublicKeyCredentialDescriptor),
    UpdateUserInformation((PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity)),
}

impl CredManagementCommand {
    fn to_id_and_param(&self) -> (u8, CredManagementParams) {
        let mut params = CredManagementParams::default();
        match &self {
            CredManagementCommand::GetCredsMetadata => (0x01, params),
            CredManagementCommand::EnumerateRPsBegin => (0x02, params),
            CredManagementCommand::EnumerateRPsGetNextRP => (0x03, params),
            CredManagementCommand::EnumerateCredentialsBegin(rp_id_hash) => {
                params.rp_id_hash = Some(rp_id_hash.clone());
                (0x04, params)
            }
            CredManagementCommand::EnumerateCredentialsGetNextCredential => (0x05, params),
            CredManagementCommand::DeleteCredential(cred_id) => {
                params.credential_id = Some(cred_id.clone());
                (0x06, params)
            }
            CredManagementCommand::UpdateUserInformation((cred_id, user)) => {
                params.credential_id = Some(cred_id.clone());
                params.user = Some(user.clone());
                (0x07, params)
            }
        }
    }
}
#[derive(Debug)]
pub struct CredentialManagement {
    pub(crate) subcommand: CredManagementCommand, // subCommand currently being requested
    pin_uv_auth_param: Option<PinUvAuthParam>, // First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken.
    use_legacy_preview: bool,
}

impl CredentialManagement {
    pub(crate) fn new(subcommand: CredManagementCommand, use_legacy_preview: bool) -> Self {
        Self {
            subcommand,
            pin_uv_auth_param: None,
            use_legacy_preview,
        }
    }
}

impl Serialize for CredentialManagement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Need to define how many elements are going to be in the map
        // beforehand
        let mut map_len = 1;
        let (id, params) = self.subcommand.to_id_and_param();
        if params.has_some() {
            map_len += 1;
        }
        if self.pin_uv_auth_param.is_some() {
            map_len += 2;
        }

        let mut map = serializer.serialize_map(Some(map_len))?;

        map.serialize_entry(&0x01, &id)?;
        if params.has_some() {
            map.serialize_entry(&0x02, &params)?;
        }

        if let Some(ref pin_uv_auth_param) = self.pin_uv_auth_param {
            map.serialize_entry(&0x03, &pin_uv_auth_param.pin_protocol.id())?;
            map.serialize_entry(&0x04, pin_uv_auth_param)?;
        }

        map.end()
    }
}

#[derive(Debug, Default)]
pub struct CredentialManagementResponse {
    /// Number of existing discoverable credentials present on the authenticator.
    pub existing_resident_credentials_count: Option<u64>,
    /// Number of maximum possible remaining discoverable credentials which can be created on the authenticator.
    pub max_possible_remaining_resident_credentials_count: Option<u64>,
    /// RP Information
    pub rp: Option<RelyingParty>,
    /// RP ID SHA-256 hash
    pub rp_id_hash: Option<RpIdHash>,
    /// Total number of RPs present on the authenticator
    pub total_rps: Option<u64>,
    /// User Information
    pub user: Option<PublicKeyCredentialUserEntity>,
    /// Credential ID
    pub credential_id: Option<PublicKeyCredentialDescriptor>,
    /// Public key of the credential.
    pub public_key: Option<COSEKey>,
    /// Total number of credentials present on the authenticator for the RP in question
    pub total_credentials: Option<u64>,
    /// Credential protection policy.
    pub cred_protect: Option<u64>,
    /// Large blob encryption key.
    pub large_blob_key: Option<Vec<u8>>,
}

impl CtapResponse for CredentialManagementResponse {}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct CredentialRpListEntry {
    /// RP Information
    pub rp: RelyingParty,
    /// RP ID SHA-256 hash
    pub rp_id_hash: RpIdHash,
    pub credentials: Vec<CredentialListEntry>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct CredentialListEntry {
    /// User Information
    pub user: PublicKeyCredentialUserEntity,
    /// Credential ID
    pub credential_id: PublicKeyCredentialDescriptor,
    /// Public key of the credential.
    pub public_key: COSEKey,
    /// Credential protection policy.
    pub cred_protect: u64,
    /// Large blob encryption key.
    pub large_blob_key: Option<Vec<u8>>,
}

#[derive(Debug, Serialize)]
pub enum CredentialManagementResult {
    CredentialList(CredentialList),
    DeleteSucess,
    UpdateSuccess,
}

#[derive(Debug, Default, Serialize)]
pub struct CredentialList {
    /// Number of existing discoverable credentials present on the authenticator.
    pub existing_resident_credentials_count: u64,
    /// Number of maximum possible remaining discoverable credentials which can be created on the authenticator.
    pub max_possible_remaining_resident_credentials_count: u64,
    /// The found credentials
    pub credential_list: Vec<CredentialRpListEntry>,
}

impl CredentialList {
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'de> Deserialize<'de> for CredentialManagementResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CredentialManagementResponseVisitor;

        impl<'de> Visitor<'de> for CredentialManagementResponseVisitor {
            type Value = CredentialManagementResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut existing_resident_credentials_count = None; // (0x01) 	Unsigned Integer 	Number of existing discoverable credentials present on the authenticator.
                let mut max_possible_remaining_resident_credentials_count = None; // (0x02) 	Unsigned Integer 	Number of maximum possible remaining discoverable credentials which can be created on the authenticator.
                let mut rp = None; // (0x03) 	PublicKeyCredentialRpEntity 	RP Information
                let mut rp_id_hash = None; // (0x04) 	Byte String 	RP ID SHA-256 hash
                let mut total_rps = None; // (0x05) 	Unsigned Integer 	total number of RPs present on the authenticator
                let mut user = None; // (0x06) 	PublicKeyCredentialUserEntity 	User Information
                let mut credential_id = None; // (0x07) 	PublicKeyCredentialDescriptor 	PublicKeyCredentialDescriptor
                let mut public_key = None; // (0x08) 	COSE_Key 	Public key of the credential.
                let mut total_credentials = None; // (0x09) 	Unsigned Integer 	Total number of credentials present on the authenticator for the RP in question
                let mut cred_protect = None; // (0x0A) 	Unsigned Integer 	Credential protection policy.
                let mut large_blob_key = None; // (0x0B) 	Byte string 	Large blob encryption key.

                while let Some(key) = map.next_key()? {
                    match key {
                        0x01 => {
                            if existing_resident_credentials_count.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "existing_resident_credentials_count",
                                ));
                            }
                            existing_resident_credentials_count = Some(map.next_value()?);
                        }
                        0x02 => {
                            if max_possible_remaining_resident_credentials_count.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "max_possible_remaining_resident_credentials_count",
                                ));
                            }
                            max_possible_remaining_resident_credentials_count =
                                Some(map.next_value()?);
                        }
                        0x03 => {
                            if rp.is_some() {
                                return Err(SerdeError::duplicate_field("rp"));
                            }
                            rp = Some(map.next_value()?);
                        }
                        0x04 => {
                            if rp_id_hash.is_some() {
                                return Err(SerdeError::duplicate_field("rp_id_hash"));
                            }
                            let rp_raw = map.next_value::<ByteBuf>()?;
                            rp_id_hash =
                                Some(RpIdHash::from(rp_raw.as_slice()).map_err(|_| {
                                    SerdeError::invalid_length(rp_raw.len(), &"32")
                                })?);
                        }
                        0x05 => {
                            if total_rps.is_some() {
                                return Err(SerdeError::duplicate_field("total_rps"));
                            }
                            total_rps = Some(map.next_value()?);
                        }
                        0x06 => {
                            if user.is_some() {
                                return Err(SerdeError::duplicate_field("user"));
                            }
                            user = Some(map.next_value()?);
                        }
                        0x07 => {
                            if credential_id.is_some() {
                                return Err(SerdeError::duplicate_field("credential_id"));
                            }
                            credential_id = Some(map.next_value()?);
                        }
                        0x08 => {
                            if public_key.is_some() {
                                return Err(SerdeError::duplicate_field("public_key"));
                            }
                            public_key = Some(map.next_value()?);
                        }
                        0x09 => {
                            if total_credentials.is_some() {
                                return Err(SerdeError::duplicate_field("total_credentials"));
                            }
                            total_credentials = Some(map.next_value()?);
                        }
                        0x0A => {
                            if cred_protect.is_some() {
                                return Err(SerdeError::duplicate_field("cred_protect"));
                            }
                            cred_protect = Some(map.next_value()?);
                        }
                        0x0B => {
                            if large_blob_key.is_some() {
                                return Err(SerdeError::duplicate_field("large_blob_key"));
                            }
                            // Using into_vec, to avoid any copy of large_blob_key
                            large_blob_key = Some(map.next_value::<ByteBuf>()?.into_vec());
                        }

                        k => {
                            warn!("ClientPinResponse: unexpected key: {:?}", k);
                            let _ = map.next_value::<IgnoredAny>()?;
                            continue;
                        }
                    }
                }

                Ok(CredentialManagementResponse {
                    existing_resident_credentials_count,
                    max_possible_remaining_resident_credentials_count,
                    rp,
                    rp_id_hash,
                    total_rps,
                    user,
                    credential_id,
                    public_key,
                    total_credentials,
                    cred_protect,
                    large_blob_key,
                })
            }
        }
        deserializer.deserialize_bytes(CredentialManagementResponseVisitor)
    }
}

impl RequestCtap2 for CredentialManagement {
    type Output = CredentialManagementResponse;

    fn command(&self) -> Command {
        if self.use_legacy_preview {
            Command::CredentialManagementPreview
        } else {
            Command::CredentialManagement
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
                trace!("parsing credential management data: {:#04X?}", &input);
                let credential_management =
                    from_slice(&input[1..]).map_err(CommandError::Deserializing)?;
                Ok(credential_management)
            } else {
                // Some subcommands return only an OK-status without any data
                Ok(CredentialManagementResponse::default())
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

impl PinUvAuthCommand for CredentialManagement {
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
            // authenticate(pinUvAuthToken, uint8(subCommand) || subCommandParams).
            let (id, params) = self.subcommand.to_id_and_param();
            let mut data = vec![id];
            if params.has_some() {
                data.extend(to_vec(&params).map_err(CommandError::Serializing)?);
            }
            param = Some(token.derive(&data).map_err(CommandError::Crypto)?);
        }
        self.pin_uv_auth_param = param;
        Ok(())
    }

    fn can_skip_user_verification(
        &mut self,
        _info: &crate::AuthenticatorInfo,
        _uv: UserVerificationRequirement,
    ) -> bool {
        // "discouraged" does not exist for AuthenticatorConfig
        false
    }

    fn set_uv_option(&mut self, _uv: Option<bool>) {
        /* No-op */
    }

    fn get_pin_uv_auth_param(&self) -> Option<&PinUvAuthParam> {
        self.pin_uv_auth_param.as_ref()
    }
}
