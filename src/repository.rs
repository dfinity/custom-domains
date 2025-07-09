use candid::Principal;
use fqdn::FQDN;
use mockall::automock;
use thiserror::Error;
use trait_async::trait_async;

use crate::{
    task::{InputTask, ScheduledTask, TaskKind, TaskResult},
    time::Timestamp,
};

#[derive(Debug, Clone, Default)]
pub struct DomainEntry {
    pub task: Option<TaskKind>,
    pub canister_id: Option<Principal>,
    pub created_at: Timestamp,
    pub taken_at: Option<Timestamp>,
    pub certificate: Option<Vec<u8>>,
    pub private_key: Option<Vec<u8>>,
    pub not_before: Option<Timestamp>,
    pub not_after: Option<Timestamp>,
}

impl DomainEntry {
    pub fn new(task: Option<TaskKind>, created_at: Timestamp) -> Self {
        Self {
            task,
            created_at,
            ..Default::default()
        }
    }
}

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("Another task is in progress for domain: {0}")]
    AnotherTaskInProgress(FQDN),
    #[error("Certificate already issued for domain: {0}")]
    CertificateAlreadyIssued(FQDN),
    #[error("Domain not found: {0}")]
    DomainNotFound(FQDN),
    #[error("Failed to submit result of a non-existing task with ID: {0}")]
    NonExistingTaskSubmitted(Timestamp),
    #[error(transparent)]
    InternalError(#[from] anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct RegisteredDomain {
    pub domain: FQDN,
    pub canister_id: Principal,
    pub cert_enc: Vec<u8>,
    pub private_key_enc: Vec<u8>,
}

#[trait_async]
#[automock]
pub trait Repository: Send + Sync {
    async fn get_domain(&self, domain: &FQDN) -> Result<Option<DomainEntry>, RepositoryError>;
    async fn fetch_next_task(&self) -> Result<Option<ScheduledTask>, RepositoryError>;
    async fn submit_task_result(&self, task: TaskResult) -> Result<(), RepositoryError>;
    async fn try_add_task(&self, task: InputTask) -> Result<(), RepositoryError>;
    /// Fetches all registered domains with valid certificates if any domain has changed (deleted/updated/or received new certificate) since the given timestamp.
    ///
    /// # Arguments
    /// * `last_sync` - Optional timestamp to check for any domain modifications since this time.
    ///
    /// # Returns
    /// * `Ok(Some(Vec<RegisteredDomain>))` containing all domains with valid certificates, if `last_sync` is `None` or if changes happened after `last_sync`.
    /// * `Ok(None)` if no domains have changed since `last_sync`.
    async fn all_registrations(
        &self,
        last_sync: Option<Timestamp>,
    ) -> Result<Option<Vec<RegisteredDomain>>, RepositoryError>;
}
