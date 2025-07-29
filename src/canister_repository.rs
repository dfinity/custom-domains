use std::sync::Arc;

use anyhow::{Error, anyhow};
use derive_new::new;
use fqdn::FQDN;
use ic_bn_lib::{
    custom_domains::{CustomDomain as IcBnCustomDomain, ProvidesCustomDomains},
    tls::providers::{Pem, ProvidesCertificates},
};
use trait_async::trait_async;

use crate::{
    crypto::CiphersCertificates,
    repository::{CustomDomain, DomainStatus, RegisteredDomain, Repository, RepositoryError},
    state::CanisterState,
    task::{InputTask, ScheduledTask, TaskOutput, TaskResult},
    time::UtcTimestamp,
};

/// An implementation of the repository which abstracts interactions with the canister.
///
/// - `certificate_cipher`: handles encryption/decryption of certificates/private_keys.
/// - `client`: performs interactions with the canister.
#[derive(Debug, new)]
pub struct CanisterRepository {
    pub certificate_cipher: Arc<dyn CiphersCertificates>,
    pub client: CanisterClient,
}

/// A client that currently wraps local State.
///
/// TODO: This is a temporary implementation. Once the actual canister is developed,
/// this client will provide a proper implementation for interacting with it via `agent-rs`.
#[derive(Debug)]
pub struct CanisterClient(pub CanisterState);

impl CanisterRepository {
    fn encrypt_field(&self, field_name: &str, data: &[u8]) -> Result<Vec<u8>, RepositoryError> {
        self.certificate_cipher.encrypt(data).map_err(|err| {
            RepositoryError::InternalError(anyhow!("failed to encrypt {field_name}: {err}"))
        })
    }

    fn decrypt_field(&self, field_name: &str, data: &[u8]) -> Result<Vec<u8>, RepositoryError> {
        self.certificate_cipher.decrypt(data).map_err(|err| {
            RepositoryError::InternalError(anyhow!("failed to decrypt {field_name}: {err}"))
        })
    }
}

#[trait_async]
impl Repository for CanisterRepository {
    async fn get_domain_status(
        &self,
        domain: &FQDN,
    ) -> Result<Option<DomainStatus>, RepositoryError> {
        self.client.0.get_domain_status(domain).await
    }

    async fn fetch_next_task(&self) -> Result<Option<ScheduledTask>, RepositoryError> {
        self.client.0.fetch_next_task().await
    }

    async fn submit_task_result(&self, mut task_result: TaskResult) -> Result<(), RepositoryError> {
        // We encrypt certificate and private_key and pass the result further to the canister.
        if let Some(TaskOutput::Issue(issued_certificate)) = &mut task_result.output {
            issued_certificate.certificate =
                self.encrypt_field("certificate", &issued_certificate.certificate)?;

            issued_certificate.private_key =
                self.encrypt_field("private key", &issued_certificate.private_key)?;
        }

        self.client.0.submit_task_result(task_result).await
    }

    async fn try_add_task(&self, task: InputTask) -> Result<(), RepositoryError> {
        self.client.0.try_add_task(task).await
    }

    async fn get_last_change_time(&self) -> Result<UtcTimestamp, RepositoryError> {
        self.client.0.get_last_change_time().await
    }

    async fn all_registrations(&self) -> Result<Vec<RegisteredDomain>, RepositoryError> {
        self.client.0.all_registrations().await
    }

    async fn all_registered_domains(&self) -> Result<Vec<CustomDomain>, RepositoryError> {
        self.client.0.all_registered_domains().await
    }
}

#[trait_async]
impl ProvidesCustomDomains for CanisterRepository {
    async fn get_custom_domains(&self) -> Result<Vec<IcBnCustomDomain>, Error> {
        let domains: Vec<_> = self.client.0.all_registered_domains().await?;

        let custom_domains = domains
            .into_iter()
            .map(|custom_domain| custom_domain.into())
            .collect();

        Ok(custom_domains)
    }
}

#[trait_async]
impl ProvidesCertificates for CanisterRepository {
    async fn get_certificates(&self) -> Result<Vec<Pem>, Error> {
        let registered_domains = self.client.0.all_registrations().await?;

        let mut pems = Vec::with_capacity(registered_domains.len());

        for domain in registered_domains {
            let certificate = self.decrypt_field("certificate", &domain.cert_encrypted)?;
            let private_key = self.decrypt_field("private key", &domain.priv_key_encrypted)?;
            pems.push(Pem([certificate, private_key].concat()));
        }

        Ok(pems)
    }
}

impl From<CustomDomain> for IcBnCustomDomain {
    fn from(value: CustomDomain) -> Self {
        IcBnCustomDomain {
            name: value.domain,
            canister_id: value.canister_id,
        }
    }
}
