use candid::Principal;
use fqdn::FQDN;
use mockall::automock;
use reqwest::{Client, Method, Request, Url};
use thiserror::Error;
use tracing::info;
use trait_async::trait_async;
use trust_dns_resolver::{
    AsyncResolver,
    config::{ResolverConfig, ResolverOpts},
    error::ResolveErrorKind,
    name_server::{ConnectionProvider, TokioConnectionProvider},
    proto::rr::RecordType,
};

use anyhow::anyhow;

const DELEGATION_DOMAIN: &str = "icp2.io";
const ACME_CHALLENGE_PREFIX: &str = "_acme-challenge";
const CANISTER_ID_PREFIX: &str = "_canister-id";

#[derive(Debug, Error)]
pub enum ValidationError {
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
}

#[trait_async]
impl ValidatesDomains for Validator<TokioConnectionProvider> {
    async fn validate(&self, domain: &FQDN) -> Result<Principal, ValidationError> {
        self.validate_no_txt_challenge(domain).await?;
        self.validate_cname_delegation(domain).await?;
        let canister_id = self.validate_canister_mapping(domain).await?;
        self.validate_canister_owner(canister_id, domain).await?;

        info!(
            domain = %domain,
            canister_id = %canister_id,
            "validation succeeded"
        );

        Ok(canister_id)
    }
}

pub struct Validator<T: ConnectionProvider> {
    delegation_domain: String,
    resolver: AsyncResolver<T>,
}

impl Default for Validator<TokioConnectionProvider> {
    fn default() -> Self {
        Self {
            delegation_domain: DELEGATION_DOMAIN.to_string(),
            resolver: AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()),
        }
    }
}

impl<T: ConnectionProvider> Validator<T> {
    pub fn new(
        delegation_domain: String,
        resolver: AsyncResolver<T>,
    ) -> Result<Self, ValidationError> {
        if delegation_domain.is_empty() {
            return Err(ValidationError::UnexpectedError(anyhow!(
                "Delegation domain cannot be empty"
            )));
        }

        Ok(Self {
            delegation_domain,
            resolver,
        })
    }

    async fn validate_canister_owner(
        &self,
        canister_id: Principal,
        domain: &FQDN,
    ) -> Result<(), ValidationError> {
        // Verify domain name is stored inside the canister, confirming canister ownership
        // TODO: verify ic-certification is handled already
        let client = Client::builder()
            .build()
            .map_err(|err| ValidationError::UnexpectedError(err.into()))?;
        let canister_id = canister_id.to_text();
        let url = Url::parse(&format!(
            "https://{canister_id}.icp0.io/.well-known/ic-domains"
        ))
        .unwrap();
        let request = Request::new(Method::GET, url);

        let response = client
            .execute(request)
            .await
            .map_err(|_| ValidationError::KnownDomainsUnavailable {
                id: canister_id.clone(),
            })?
            .text()
            .await
            .map_err(|err| ValidationError::UnexpectedError(err.into()))?;

        response
            .contains(&domain.to_string())
            .then_some(())
            .ok_or(ValidationError::MissingKnownDomains { id: canister_id })
    }

    async fn validate_no_txt_challenge(&self, domain: &FQDN) -> Result<(), ValidationError> {
        let txt_src = format!("{ACME_CHALLENGE_PREFIX}.{domain}.");

        match self.resolver.lookup(&txt_src, RecordType::TXT).await {
            Ok(lookup) => {
                // Check all records belong to delegation domain
                lookup
                    .record_iter()
                    .all(|rec| {
                        let name = rec.name().to_string().trim_end_matches('.').to_owned();
                        name.ends_with(&self.delegation_domain)
                    })
                    .then_some(())
                    .ok_or(ValidationError::ExistingDnsTxtChallenge { src: txt_src })
            }
            Err(err) => match err.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => Ok(()),
                _ => Err(ValidationError::UnexpectedError(anyhow!(
                    "Failed to resolve TXT record for {}: {}",
                    txt_src,
                    err
                ))),
            },
        }
    }

    async fn validate_cname_delegation(&self, domain: &FQDN) -> Result<(), ValidationError> {
        let cname_src = format!("{ACME_CHALLENGE_PREFIX}.{domain}.");
        let cname_dst = format!(
            "{ACME_CHALLENGE_PREFIX}.{domain}.{}.",
            self.delegation_domain
        );

        // Resolve CNAME record
        let records = self
            .resolver
            .lookup(&cname_src, RecordType::CNAME)
            .await
            .map_err(|err| match err.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => ValidationError::MissingDnsCname {
                    src: cname_src.clone(),
                    dst: cname_dst.clone(),
                },
                _ => ValidationError::UnexpectedError(anyhow!(
                    "Failed to resolve CNAME from {}: {}",
                    cname_src,
                    err
                )),
            })?;

        // Validate expected CNAME record exists
        records
            .iter()
            .any(|record| record.to_string() == cname_dst)
            .then_some(())
            .ok_or(ValidationError::MissingDnsCname {
                src: cname_src,
                dst: cname_dst,
            })
    }

    async fn validate_canister_mapping(&self, domain: &FQDN) -> Result<Principal, ValidationError> {
        let txt_src = format!("{CANISTER_ID_PREFIX}.{domain}");

        // Resolve TXT record
        let records = self
            .resolver
            .lookup(&txt_src, RecordType::TXT)
            .await
            .map_err(|err| match err.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => {
                    ValidationError::MissingDnsTxtCanisterId {
                        src: txt_src.clone(),
                    }
                }
                _ => ValidationError::UnexpectedError(anyhow!(
                    "Failed to resolve TXT record at {}: {}",
                    txt_src,
                    err
                )),
            })?;

        // Validate exactly one record exists
        let mut record_iter = records.iter();
        let first_record =
            record_iter
                .next()
                .ok_or_else(|| ValidationError::MissingDnsTxtCanisterId {
                    src: txt_src.clone(),
                })?;

        if record_iter.next().is_some() {
            return Err(ValidationError::MultipleDnsTxtCanisterId { src: txt_src });
        }

        // Parse canister ID
        let canister_id_str = first_record.to_string();
        Principal::from_text(&canister_id_str).map_err(|_| {
            ValidationError::InvalidDnsTxtCanisterId {
                src: txt_src,
                id: canister_id_str,
            }
        })
    }
}
