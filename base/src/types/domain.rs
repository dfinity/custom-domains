use std::str::FromStr;

use candid::Principal;
use canister_api::{
    DomainStatus as ApiDomainStatus, RegisteredDomain as ApiRegisteredDomain,
    RegistrationStatus as ApiRegistrationStatus,
};
use derive_new::new;
use fqdn::FQDN;
use serde::{Deserialize, Serialize, Serializer};

/// Represents a fully registered domain with encrypted certificate and private key.
#[derive(Debug, Clone, new)]
pub struct RegisteredDomain {
    /// The fully qualified domain name
    pub domain: FQDN,
    /// The canister ID associated with this domain
    pub canister_id: Principal,
    /// The encrypted certificate data
    pub cert_encrypted: Vec<u8>,
    /// The encrypted private key data
    pub priv_key_encrypted: Vec<u8>,
}

/// Represents the status of a domain registration process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    /// The registration is currently being processed
    Registering,
    /// The domain has been successfully registered and has a valid certificate
    Registered,
    /// The domain registration has expired
    Expired,
    /// The registration failed with an error message.
    /// Note: The message is not exposed directly in API responses.
    #[serde(serialize_with = "serialize_failed")]
    Failed(String),
}

fn serialize_failed<S>(_: &String, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(
        "An unexpected error occurred during registration. Please try again later or contact support.",
    )
}

/// Represents the overall status of a domain including registration state.
#[derive(Debug, Clone)]
pub struct DomainStatus {
    /// The fully qualified domain name
    pub domain: FQDN,
    /// The canister ID if the domain is registered
    pub canister_id: Option<Principal>,
    /// The current registration status
    pub status: RegistrationStatus,
}

impl TryFrom<ApiDomainStatus> for DomainStatus {
    type Error = anyhow::Error;

    fn try_from(api_status: ApiDomainStatus) -> Result<Self, Self::Error> {
        let status = match api_status.status {
            ApiRegistrationStatus::Registering => RegistrationStatus::Registering,
            ApiRegistrationStatus::Registered => RegistrationStatus::Registered,
            ApiRegistrationStatus::Expired => RegistrationStatus::Expired,
            ApiRegistrationStatus::Failed(reason) => RegistrationStatus::Failed(reason),
        };

        Ok(DomainStatus {
            domain: FQDN::from_str(&api_status.domain)?,
            canister_id: api_status.canister_id,
            status,
        })
    }
}

impl From<ApiRegistrationStatus> for RegistrationStatus {
    fn from(status: ApiRegistrationStatus) -> Self {
        match status {
            ApiRegistrationStatus::Registering => RegistrationStatus::Registering,
            ApiRegistrationStatus::Registered => RegistrationStatus::Registered,
            ApiRegistrationStatus::Expired => RegistrationStatus::Expired,
            ApiRegistrationStatus::Failed(reason) => RegistrationStatus::Failed(reason),
        }
    }
}

impl TryFrom<ApiRegisteredDomain> for RegisteredDomain {
    type Error = anyhow::Error;

    fn try_from(value: ApiRegisteredDomain) -> Result<Self, Self::Error> {
        Ok(RegisteredDomain {
            domain: FQDN::from_str(&value.domain)?,
            canister_id: value.canister_id,
            cert_encrypted: value.cert_encrypted,
            priv_key_encrypted: value.priv_key_encrypted,
        })
    }
}
