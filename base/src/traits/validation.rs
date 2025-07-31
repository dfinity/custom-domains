use candid::Principal;
use fqdn::FQDN;
use mockall::automock;
use thiserror::Error;
use trait_async::trait_async;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("existing DNS TXT _canister-id record at {src}")]
    ExistingDnsTxtCanisterId { src: String },
    #[error("existing DNS TXT challenge record at {src}")]
    ExistingDnsTxtChallenge { src: String },
    #[error("missing DNS CNAME record from {src} to {dst}")]
    MissingDnsCname { src: String, dst: String },
    #[error("missing DNS TXT record from {src} to a canister id")]
    MissingDnsTxtCanisterId { src: String },
    #[error("multiple DNS TXT records for canister id at {src}")]
    MultipleDnsTxtCanisterId { src: String },
    #[error("invalid DNS TXT record from {src} to {id}")]
    InvalidDnsTxtCanisterId { src: String, id: String },
    #[error("failed to retrieve known domains from canister {id}")]
    KnownDomainsUnavailable { id: String },
    #[error("domain is missing from canister {id} list of known domains")]
    MissingKnownDomains { id: String },
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[trait_async]
#[automock]
pub trait ValidatesDomains: Send + Sync {
    async fn validate(&self, domain: &FQDN) -> Result<Principal, ValidationError>;
    async fn validate_deletion(&self, domain: &FQDN) -> Result<(), ValidationError>;
}
