use anyhow::anyhow;
use candid::Principal;
use fqdn::FQDN;
use reqwest::{Client, Method, Request, Url};
use trait_async::trait_async;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    error::ResolveErrorKind,
    name_server::{ConnectionProvider, TokioConnectionProvider},
    proto::rr::RecordType,
    AsyncResolver,
};

use crate::traits::validation::{ValidatesDomains, ValidationError};

const DEFAULT_DELEGATION_DOMAIN: &str = "icp2.io";
const DEFAULT_ACME_CHALLENGE_PREFIX: &str = "_acme-challenge";
const DEFAULT_CANISTER_ID_PREFIX: &str = "_canister-id";

/// DNS validator for custom domain registration.
///
/// Validates that a domain is properly configured for custom domain registration
/// by checking DNS records, CNAME delegation, and canister ownership.
pub struct Validator<T: ConnectionProvider> {
    resolver: AsyncResolver<T>,
    dns_config: DnsConfig,
}

#[trait_async]
impl ValidatesDomains for Validator<TokioConnectionProvider> {
    async fn validate(&self, domain: &FQDN) -> Result<Principal, ValidationError> {
        self.validate_no_txt_challenge(domain).await?;
        self.validate_cname_delegation(domain).await?;
        let canister_id = self.validate_canister_mapping(domain).await?;
        self.validate_canister_owner(canister_id, domain).await?;
        Ok(canister_id)
    }

    async fn validate_deletion(&self, domain: &FQDN) -> Result<(), ValidationError> {
        self.validate_no_canister_id_record(domain).await
    }
}

/// Configuration for DNS validation settings.
pub struct DnsConfig {
    /// The delegation domain (e.g., "icp2.io")
    pub delegation_domain: String,
    /// The prefix for ACME challenge records (e.g., "_acme-challenge")
    pub acme_challenge_prefix: String,
    /// The prefix for canister ID records (e.g., "_canister-id")
    pub canister_id_prefix: String,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            delegation_domain: DEFAULT_DELEGATION_DOMAIN.to_string(),
            acme_challenge_prefix: DEFAULT_ACME_CHALLENGE_PREFIX.to_string(),
            canister_id_prefix: DEFAULT_CANISTER_ID_PREFIX.to_string(),
        }
    }
}

impl Default for Validator<TokioConnectionProvider> {
    fn default() -> Self {
        // Use non-caching configuration as default
        Self::new_without_cache(DnsConfig::default()).unwrap()
    }
}

impl<T: ConnectionProvider> Validator<T> {
    /// Create a new Validator with custom resolver and DNS configuration
    pub fn new(resolver: AsyncResolver<T>, dns_config: DnsConfig) -> Result<Self, ValidationError> {
        if dns_config.delegation_domain.is_empty() {
            return Err(ValidationError::UnexpectedError(anyhow!(
                "Delegation domain cannot be empty"
            )));
        }

        Ok(Self {
            resolver,
            dns_config,
        })
    }
}

impl Validator<TokioConnectionProvider> {
    /// Create a new Validator without DNS caching (useful for real-time validation)
    pub fn new_without_cache(dns_config: DnsConfig) -> Result<Self, ValidationError> {
        if dns_config.delegation_domain.is_empty() {
            return Err(ValidationError::UnexpectedError(anyhow!(
                "Delegation domain cannot be empty"
            )));
        }

        let mut opts = ResolverOpts::default();
        opts.cache_size = 0;
        opts.use_hosts_file = false;
        opts.validate = false;
        opts.recursion_desired = true;

        let resolver = AsyncResolver::tokio(ResolverConfig::default(), opts);

        Ok(Self {
            resolver,
            dns_config,
        })
    }

    /// Validates that the canister declares ownership of the domain.
    ///
    /// Checks the /.well-known/ic-domains asset of the canister to verify
    /// that the domain is listed as a known domain for that canister.
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

    /// Validates that there are no existing canister ID TXT records for the domain.
    ///
    /// This check ensures the domain can be safely deleted or is not already registered.
    async fn validate_no_canister_id_record(&self, domain: &FQDN) -> Result<(), ValidationError> {
        let txt_src = format!("{}.{domain}.", self.dns_config.canister_id_prefix);

        match self.resolver.lookup(&txt_src, RecordType::TXT).await {
            Ok(_) => Err(ValidationError::ExistingDnsTxtCanisterId { src: txt_src }),
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

    /// Validates that there are no conflicting ACME challenge TXT records.
    ///
    /// Ensures that any existing ACME challenge records point to the delegation domain
    /// or that no conflicting records exist that would interfere with certificate issuance.
    async fn validate_no_txt_challenge(&self, domain: &FQDN) -> Result<(), ValidationError> {
        let txt_src = format!("{}.{domain}.", self.dns_config.acme_challenge_prefix);

        match self.resolver.lookup(&txt_src, RecordType::TXT).await {
            Ok(lookup) => {
                // Check all records belong to delegation domain
                lookup
                    .record_iter()
                    .all(|rec| {
                        let name = rec.name().to_string().trim_end_matches('.').to_owned();
                        name.ends_with(&self.dns_config.delegation_domain)
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

    /// Validates that the domain has proper CNAME delegation set up.
    ///
    /// Checks that the ACME challenge subdomain has a CNAME record pointing
    /// to the corresponding delegation domain for certificate validation.
    async fn validate_cname_delegation(&self, domain: &FQDN) -> Result<(), ValidationError> {
        let cname_src = format!("{}.{domain}.", self.dns_config.acme_challenge_prefix);
        let cname_dst = format!(
            "{}.{domain}.{}.",
            self.dns_config.acme_challenge_prefix, self.dns_config.delegation_domain
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

    /// Validates and extracts the canister ID from DNS TXT records.
    ///
    /// Looks for a TXT record at the canister ID prefix subdomain and validates
    /// that exactly one record exists containing a valid canister Principal.
    async fn validate_canister_mapping(&self, domain: &FQDN) -> Result<Principal, ValidationError> {
        let txt_src = format!("{}.{domain}", self.dns_config.canister_id_prefix);

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
