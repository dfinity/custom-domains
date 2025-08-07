use candid::Principal;
use derive_new::new;
use fqdn::FQDN;
use ic_bn_lib::custom_domains::CustomDomain as IcBnCustomDomain;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, new)]
pub struct RegisteredDomain {
    pub domain: FQDN,
    pub canister_id: Principal,
    pub cert_encrypted: Vec<u8>,
    pub priv_key_encrypted: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomDomain {
    pub domain: FQDN,
    pub canister_id: Principal,
}

impl From<CustomDomain> for IcBnCustomDomain {
    fn from(value: CustomDomain) -> Self {
        IcBnCustomDomain {
            name: value.domain,
            canister_id: value.canister_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Processing,
    Registered,
    Failure(String),
}

#[derive(Debug, Clone)]
pub struct DomainStatus {
    pub domain: FQDN,
    pub canister_id: Option<Principal>,
    pub status: RegistrationStatus,
}
