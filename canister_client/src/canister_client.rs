//! # Canister Client
//!
//! This module provides a client for interacting with the custom domains canister.
//! It handles all communication, serialization, encryption, and error handling.

use std::sync::{atomic::AtomicU64, atomic::Ordering, Arc};

use anyhow::anyhow;
use arc_swap::ArcSwap;
use base::{
    traits::{
        cipher::CiphersCertificates,
        repository::{Repository, RepositoryError},
        time::UtcTimestamp,
    },
    types::{
        domain::{DomainStatus, RegisteredDomain},
        task::{InputTask, ScheduledTask, TaskOutput, TaskResult},
    },
};
use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use canister_api::ListCertificatesPageInput;
use derive_new::new;
use fqdn::FQDN;
use ic_agent::Agent;
use ic_bn_lib::{
    custom_domains::{CustomDomain as IcBnCustomDomain, ProvidesCustomDomains},
    tls::providers::{Pem, ProvidesCertificates},
};
use trait_async::trait_async;

#[derive(Debug, new)]
pub struct CanisterClient {
    agent: Agent,
    canister_id: Principal,
    certificate_cipher: Arc<dyn CiphersCertificates>,
    #[new(value = "AtomicU64::new(0)")]
    last_change_time: AtomicU64,
    #[new(value = "ArcSwap::from_pointee(Vec::new())")]
    certificates: ArcSwap<Vec<Pem>>,
    #[new(value = "ArcSwap::from_pointee(Vec::new())")]
    custom_domains: ArcSwap<Vec<IcBnCustomDomain>>,
}

impl CanisterClient {
    /// Method to fetch and cache registrations if changes happened.
    async fn maybe_update_cache(&self) -> Result<(), anyhow::Error> {
        let last_change = self.get_last_change_time().await?;
        let cached_timestamp = self.last_change_time.load(Ordering::Relaxed);

        if last_change != cached_timestamp {
            // Certificates have changed, fetch new ones
            let registered_domains = self.all_registrations().await?;

            let mut pems = Vec::with_capacity(registered_domains.len());
            let mut domains = Vec::with_capacity(registered_domains.len());

            for domain in registered_domains {
                let certificate = self.decrypt_field(&domain.cert_encrypted)?;
                let private_key = self.decrypt_field(&domain.priv_key_encrypted)?;

                pems.push(Pem([certificate, private_key].concat()));

                domains.push(IcBnCustomDomain {
                    name: domain.domain,
                    canister_id: domain.canister_id,
                });
            }

            // Update cache
            self.certificates.store(Arc::new(pems));
            self.custom_domains.store(Arc::new(domains));
            self.last_change_time.store(last_change, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Encrypts sensitive data before sending it to canister
    fn encrypt_field(&self, field_name: &str, data: &[u8]) -> Result<Vec<u8>, RepositoryError> {
        self.certificate_cipher.encrypt(data).map_err(|err| {
            RepositoryError::InternalError(anyhow!("Failed to encrypt {field_name}: {err}"))
        })
    }

    /// Decrypts sensitive data received from canister
    fn decrypt_field(&self, data: &[u8]) -> Result<Vec<u8>, RepositoryError> {
        self.certificate_cipher
            .decrypt(data)
            .map_err(|err| RepositoryError::InternalError(anyhow!("Failed to decrypt data: {err}")))
    }

    /// Makes a query call to the canister, decodes the response, and handles canister API errors
    async fn query<T, R, E>(&self, method: &str, args: &T) -> Result<R, RepositoryError>
    where
        T: CandidType,
        R: for<'de> Deserialize<'de> + CandidType,
        E: for<'de> Deserialize<'de> + CandidType + std::fmt::Debug,
        RepositoryError: TryFrom<E>,
    {
        let arg = Encode!(args).map_err(|err| {
            RepositoryError::InternalError(anyhow!(
                "Failed to encode arguments for {method}: {err}"
            ))
        })?;

        let result = self
            .agent
            .query(&self.canister_id, method)
            .with_arg(arg)
            .call()
            .await
            .map_err(|err| {
                RepositoryError::InternalError(anyhow!("Canister query {method} failed: {err}"))
            })?;

        let response = Decode!(&result, Result<R, E>).map_err(|err| {
            RepositoryError::InternalError(anyhow!("Failed to decode {method} response: {err}"))
        })?;

        response.map_err(|err| {
            let err_debug = format!("{err:?}");
            match RepositoryError::try_from(err) {
                Ok(repo_err) => repo_err,
                Err(_) => RepositoryError::InternalError(anyhow!(
                    "Failed to convert canister error: {err_debug}"
                )),
            }
        })
    }

    /// Makes an update call to the canister, decodes the response, and handles canister API errors
    async fn update<T, R, E>(&self, method: &str, args: &T) -> Result<R, RepositoryError>
    where
        T: CandidType,
        R: for<'de> Deserialize<'de> + CandidType,
        E: for<'de> Deserialize<'de> + CandidType + std::fmt::Debug,
        RepositoryError: TryFrom<E>,
    {
        let arg = Encode!(args).map_err(|err| {
            RepositoryError::InternalError(anyhow!(
                "Failed to encode arguments for {method}: {err}"
            ))
        })?;

        let result = self
            .agent
            .update(&self.canister_id, method)
            .with_arg(arg)
            .call_and_wait()
            .await
            .map_err(|err| {
                RepositoryError::InternalError(anyhow!("Canister update {method} failed: {err}"))
            })?;

        let response = Decode!(&result, Result<R, E>).map_err(|err| {
            RepositoryError::InternalError(anyhow!("Failed to decode {method} response: {err}"))
        })?;

        response.map_err(|err| {
            let err_debug = format!("{err:?}");
            match RepositoryError::try_from(err) {
                Ok(repo_err) => repo_err,
                Err(_) => RepositoryError::InternalError(anyhow!(
                    "Failed to convert canister error: {err_debug}"
                )),
            }
        })
    }
}

#[trait_async]
impl Repository for CanisterClient {
    async fn get_domain_status(
        &self,
        domain: &FQDN,
    ) -> Result<Option<DomainStatus>, RepositoryError> {
        let response = self
            .query::<String, Option<canister_api::DomainStatus>, canister_api::GetDomainStatusError>(
                "get_domain_status", 
                &domain.to_string()
            )
            .await?;

        match response {
            None => Ok(None),
            Some(api_status) => {
                let status = DomainStatus::try_from(api_status).map_err(|err| {
                    RepositoryError::InternalError(anyhow!(
                        "Failed to convert domain status: {err}"
                    ))
                })?;
                Ok(Some(status))
            }
        }
    }

    async fn fetch_next_task(&self) -> Result<Option<ScheduledTask>, RepositoryError> {
        let has_next_task = self
            .query::<(), bool, canister_api::HasNextTaskError>("has_next_task", &())
            .await?;

        if !has_next_task {
            return Ok(None);
        }

        let response = self
            .update::<(), Option<canister_api::ScheduledTask>, canister_api::FetchTaskError>(
                "fetch_next_task",
                &(),
            )
            .await?;

        match response {
            None => Ok(None),
            Some(api_task) => {
                let task = ScheduledTask::try_from(api_task).map_err(|err| {
                    RepositoryError::InternalError(anyhow!(
                        "Failed to convert scheduled task: {err}"
                    ))
                })?;
                Ok(Some(task))
            }
        }
    }

    async fn submit_task_result(&self, mut task_result: TaskResult) -> Result<(), RepositoryError> {
        // We encrypt certificate and private_key and pass the result further to the canister.
        if let Some(TaskOutput::Issue(issued_certificate)) = &mut task_result.output {
            issued_certificate.certificate =
                self.encrypt_field("certificate", &issued_certificate.certificate)?;

            issued_certificate.private_key =
                self.encrypt_field("private key", &issued_certificate.private_key)?;
        }

        self.update::<canister_api::TaskResult, (), canister_api::SubmitTaskError>(
            "submit_task_result",
            &canister_api::TaskResult::from(task_result),
        )
        .await?;

        Ok(())
    }

    async fn try_add_task(&self, input_task: InputTask) -> Result<(), RepositoryError> {
        let response = self
            .update::<canister_api::InputTask, (), canister_api::TryAddTaskError>(
                "try_add_task",
                &canister_api::InputTask::from(input_task),
            )
            .await;

        response?;

        Ok(())
    }

    async fn get_last_change_time(&self) -> Result<UtcTimestamp, RepositoryError> {
        let response = self
            .query::<(), UtcTimestamp, canister_api::GetLastChangeTimeError>(
                "get_last_change_time",
                &(),
            )
            .await?;

        Ok(response)
    }

    async fn all_registrations(&self) -> Result<Vec<RegisteredDomain>, RepositoryError> {
        let mut registered_domains = vec![];
        let mut start_key = None;

        loop {
            let response = self
            .query::<ListCertificatesPageInput, canister_api::CertificatesPage, canister_api::ListCertificatesPageError>(
                "list_certificates_page",
                &ListCertificatesPageInput {
                    start_key,
                    limit: None,
                },
            )
            .await?;

            let registrations = response
                .items
                .into_iter()
                .map(|reg| {
                    RegisteredDomain::try_from(reg).map_err(|err| {
                        RepositoryError::InternalError(anyhow!(
                            "Failed to convert RegisteredDomain: {err}"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            registered_domains.extend(registrations);
            start_key = response.next_key;

            if start_key.is_none() {
                break;
            }
        }

        Ok(registered_domains)
    }
}

#[trait_async]
impl ProvidesCertificates for CanisterClient {
    async fn get_certificates(&self) -> Result<Vec<Pem>, anyhow::Error> {
        self.maybe_update_cache().await?;
        Ok(self.certificates.load().as_ref().clone())
    }
}

#[trait_async]
impl ProvidesCustomDomains for CanisterClient {
    async fn get_custom_domains(&self) -> Result<Vec<IcBnCustomDomain>, anyhow::Error> {
        self.maybe_update_cache().await?;
        Ok(self.custom_domains.load().as_ref().clone())
    }
}
