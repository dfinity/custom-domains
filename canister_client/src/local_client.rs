use anyhow::anyhow;
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
use derive_new::new;
use fqdn::FQDN;
use std::sync::Arc;
use trait_async::trait_async;

use crate::local_state::LocalState;

/// An implementation of the repository with a local state.
///
/// This repository manages domain certificates and tasks using local storage
/// rather than interacting with a remote canister. Useful for testing and
/// development scenarios.
///
/// - `certificate_cipher`: handles encryption/decryption of certificates/private_keys.
/// - `state`: manages local storage of domain and task data.
#[derive(Debug, new)]
pub struct LocalRepository {
    /// Cipher for encrypting/decrypting sensitive certificate data
    pub certificate_cipher: Arc<dyn CiphersCertificates>,
    /// Local state storage for domains and tasks
    pub state: LocalState,
}

impl LocalRepository {
    /// Encrypts sensitive field data for secure storage.
    fn encrypt_field(&self, field_name: &str, data: &[u8]) -> Result<Vec<u8>, RepositoryError> {
        self.certificate_cipher.encrypt(data).map_err(|err| {
            RepositoryError::InternalError(anyhow!("failed to encrypt {field_name}: {err}"))
        })
    }
}

#[trait_async]
impl Repository for LocalRepository {
    async fn get_domain_status(
        &self,
        domain: &FQDN,
    ) -> Result<Option<DomainStatus>, RepositoryError> {
        self.state.get_domain_status(domain).await
    }

    async fn fetch_next_task(&self) -> Result<Option<ScheduledTask>, RepositoryError> {
        self.state.fetch_next_task().await
    }

    async fn submit_task_result(&self, mut task_result: TaskResult) -> Result<(), RepositoryError> {
        // We encrypt certificate and private_key and pass the result further to the canister.
        if let Some(TaskOutput::Issue(issued_certificate)) = &mut task_result.output {
            issued_certificate.certificate =
                self.encrypt_field("certificate", &issued_certificate.certificate)?;

            issued_certificate.private_key =
                self.encrypt_field("private key", &issued_certificate.private_key)?;
        }

        self.state.submit_task_result(task_result).await
    }

    async fn try_add_task(&self, input_task: InputTask) -> Result<(), RepositoryError> {
        self.state.try_add_task(input_task).await
    }

    async fn get_last_change_time(&self) -> Result<UtcTimestamp, RepositoryError> {
        self.state.get_last_change_time().await
    }

    async fn all_registrations(&self) -> Result<Vec<RegisteredDomain>, RepositoryError> {
        self.state.all_registrations().await
    }
}
