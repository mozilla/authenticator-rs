use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde_cbor::Value;

use crate::ctap::ClientDataHash;
use crate::ctap2::commands::{MakeCredentialsOptions, PinAuth};
use crate::ctap2::server::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, RelyingParty, User,
};

#[derive(Debug)]
pub struct MakeCredentials {
    client_data: ClientDataHash,
    rp: RelyingParty,
    user: User,
    pub_cred_params: Vec<PublicKeyCredentialParameters>,
    exclude_list: Vec<PublicKeyCredentialDescriptor>,
    extensions: BTreeMap<String, Value>,
    options: Option<MakeCredentialsOptions>,
    pin_auth: Option<PinAuth>,
    pin_protocol: Option<u8>,
}

impl MakeCredentials {
    pub fn rp(&self) -> &RelyingParty {
        &self.rp
    }
}

impl<'de> Deserialize<'de> for MakeCredentials {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MakeCredentialsVisitor;

        impl<'de> Visitor<'de> for MakeCredentialsVisitor {
            type Value = MakeCredentials;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut client_data = None;
                let mut rp = None;
                let mut user = None;
                let mut pub_cred_params = Vec::new();
                let mut exclude_list = Vec::new();
                let mut extensions = BTreeMap::new();
                let mut options = None;
                let mut pin_auth = None;
                let mut pin_protocol = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        1 => {
                            if client_data.is_some() {
                                return Err(de::Error::duplicate_field("client_data"));
                            }
                            client_data = Some(map.next_value()?);
                        }
                        2 => {
                            if rp.is_some() {
                                return Err(de::Error::duplicate_field("rp"));
                            }
                            rp = Some(map.next_value()?);
                        }
                        3 => {
                            if user.is_some() {
                                return Err(de::Error::duplicate_field("user"));
                            }
                            user = Some(map.next_value()?);
                        }
                        4 => {
                            if !pub_cred_params.is_empty() {
                                return Err(de::Error::duplicate_field("pub_cred_params"));
                            }
                            pub_cred_params = map.next_value()?;
                        }
                        5 => {
                            if !exclude_list.is_empty() {
                                return Err(de::Error::duplicate_field("exclude_list"));
                            }
                            exclude_list = map.next_value()?;
                        }
                        6 => {
                            if !extensions.is_empty() {
                                return Err(de::Error::duplicate_field("extensions"));
                            }
                            extensions = map.next_value()?;
                        }
                        7 => {
                            if options.is_some() {
                                return Err(de::Error::duplicate_field("options"));
                            }
                            options = Some(map.next_value()?);
                        }
                        8 => {
                            if pin_auth.is_some() {
                                return Err(de::Error::duplicate_field("pin_auth"));
                            }
                            pin_auth = Some(map.next_value()?);
                        }
                        9 => {
                            if pin_protocol.is_some() {
                                return Err(de::Error::duplicate_field("pin_protocol"));
                            }
                            pin_protocol = Some(map.next_value()?);
                        }
                        v => {
                            return Err(de::Error::unknown_field(&format!("{}", v), &[]));
                        }
                    }
                }

                let client_data = client_data.ok_or(de::Error::missing_field("client_data"))?;
                let rp = rp.ok_or(de::Error::missing_field("rp"))?;
                let user = user.ok_or(de::Error::missing_field("user"))?;

                Ok(MakeCredentials {
                    client_data,
                    rp,
                    user,
                    pub_cred_params,
                    exclude_list,
                    extensions,
                    options,
                    pin_auth,
                    pin_protocol,
                })
            }
        }

        deserializer.deserialize_bytes(MakeCredentialsVisitor)
    }
}
