use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use candid::Principal;
use fqdn::{fqdn, FQDN};
use hickory_resolver::proto::rr::RecordType;
use ic_bn_lib::{
    http::{
        client::Options as HttpOptions,
        dns::{Options as DnsOptions, Resolver, Resolves, SingleResolver},
        Client, ReqwestClient,
    },
    reqwest::{Method, Request, Url},
};

use crate::traits::validation::{ValidatesDomains, ValidationError};

/// DNS validator for custom domain registration.
///
/// Validates that a domain is properly configured for custom domain registration
/// by checking DNS records, CNAME delegation, and canister ownership.
pub struct Validator {
    client: Arc<dyn Client>,
    resolver: Arc<dyn Resolves>,
    delegation_domain: FQDN,
    validation_domain: FQDN,
}

#[async_trait]
impl ValidatesDomains for Validator {
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

impl Default for Validator {
    fn default() -> Self {
        Self::new(fqdn!("icp2.io"), fqdn!("icp0.io"), DnsOptions::default()).unwrap()
    }
}

impl Validator {
    /// Create a new Validator
    pub fn new(
        delegation_domain: FQDN,
        validation_domain: FQDN,
        mut dns_opts: DnsOptions,
    ) -> Result<Self, ValidationError> {
        if delegation_domain.is_root() {
            return Err(ValidationError::UnexpectedError(anyhow!(
                "Delegation domain cannot be empty"
            )));
        }

        dns_opts.cache_size = 0;
        let resolver = Resolver::new(dns_opts);

        let http_opts = HttpOptions::default();
        let http_resolver = SingleResolver::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let client = ReqwestClient::new(http_opts, Some(http_resolver))
            .context("unable to create HTTP client")?;

        Ok(Self {
            client: Arc::new(client),
            resolver: Arc::new(resolver),
            delegation_domain,
            validation_domain,
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
        let url = format!(
            "https://{canister_id}.{}/.well-known/ic-domains",
            self.validation_domain
        );

        let request = Request::new(
            Method::GET,
            Url::parse(&url).map_err(|e| ValidationError::UnexpectedError(e.into()))?,
        );

        let response = self
            .client
            .execute(request)
            .await
            .map_err(|e| ValidationError::KnownDomainsUnavailable {
                id: canister_id.to_string(),
                error: e.to_string(),
            })?
            .text()
            .await
            .map_err(|err| ValidationError::UnexpectedError(err.into()))?;

        response.contains(&domain.to_string()).then_some(()).ok_or(
            ValidationError::MissingKnownDomains {
                id: canister_id.to_string(),
            },
        )
    }

    /// Validates that there are no existing canister ID TXT records for the domain.
    ///
    /// This check ensures the domain can be safely deleted or is not already registered.
    async fn validate_no_canister_id_record(&self, domain: &FQDN) -> Result<(), ValidationError> {
        let hostname = format!("_canister-id.{domain}.");

        match self.resolver.resolve(RecordType::TXT, &hostname).await {
            Ok(_) => Err(ValidationError::ExistingDnsTxtCanisterId { src: hostname }),
            Err(err) => {
                if err.is_no_records_found() || err.is_nx_domain() {
                    Ok(())
                } else {
                    Err(ValidationError::UnexpectedError(anyhow!(
                        "Failed to resolve TXT record for {hostname}: {err}"
                    )))
                }
            }
        }
    }

    /// Validates that there are no conflicting ACME challenge TXT records.
    ///
    /// Ensures that any existing ACME challenge records point to the delegation domain
    /// or that no conflicting records exist that would interfere with certificate issuance.
    async fn validate_no_txt_challenge(&self, domain: &FQDN) -> Result<(), ValidationError> {
        let hostname = format!("_acme-challenge.{domain}.");

        match self.resolver.resolve(RecordType::TXT, &hostname).await {
            Ok(lookup) => {
                // If there are records - check that all of them belong to the delegation domain
                for rr in lookup {
                    let name = rr.to_string();
                    let name = FQDN::from_ascii_str(&rr.to_string())
                        .context(format!("unable to parse '{name}' as FQDN"))?;

                    if !name.is_subdomain_of(&self.delegation_domain) {
                        return Err(ValidationError::ExistingDnsTxtChallenge { src: hostname });
                    }
                }

                Ok(())
            }

            Err(err) => {
                if err.is_no_records_found() || err.is_nx_domain() {
                    Ok(())
                } else {
                    Err(ValidationError::UnexpectedError(anyhow!(
                        "Failed to resolve TXT record for {hostname}: {err}",
                    )))
                }
            }
        }
    }

    /// Validates that the domain has proper CNAME delegation set up.
    ///
    /// Checks that the ACME challenge subdomain has a CNAME record pointing
    /// to the corresponding delegation domain for certificate validation.
    async fn validate_cname_delegation(&self, domain: &FQDN) -> Result<(), ValidationError> {
        let cname_src = format!("_acme-challenge.{domain}.");
        let cname_dst = format!("_acme-challenge.{domain}.{}.", self.delegation_domain);

        // Resolve CNAME record
        let records = self
            .resolver
            .resolve(RecordType::CNAME, &cname_src)
            .await
            .map_err(|err| {
                if err.is_no_records_found() || err.is_nx_domain() {
                    ValidationError::MissingDnsCname {
                        src: cname_src.clone(),
                        dst: cname_dst.clone(),
                    }
                } else {
                    ValidationError::UnexpectedError(anyhow!(
                        "Failed to resolve CNAME from {cname_src}: {err}"
                    ))
                }
            })?;

        // Validate expected CNAME record exists
        records
            .iter()
            .any(|rr| rr.to_string() == cname_dst)
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
        let hostname = format!("_canister-id.{domain}");

        // Resolve TXT record
        let records = self
            .resolver
            .resolve(RecordType::TXT, &hostname)
            .await
            .map_err(|err| {
                if err.is_no_records_found() || err.is_nx_domain() {
                    ValidationError::MissingDnsTxtCanisterId {
                        src: hostname.clone(),
                    }
                } else {
                    ValidationError::UnexpectedError(anyhow!(
                        "Failed to resolve TXT record at {hostname}: {err}",
                    ))
                }
            })?;

        // Make sure there's exactly one record
        if records.is_empty() {
            return Err(ValidationError::MissingDnsTxtCanisterId { src: hostname });
        }

        if records.len() > 1 {
            return Err(ValidationError::MultipleDnsTxtCanisterId { src: hostname });
        }

        let rr = records[0].to_string();

        // Parse canister ID
        Principal::from_text(&rr).map_err(|_| ValidationError::InvalidDnsTxtCanisterId {
            src: hostname,
            id: rr,
        })
    }
}
