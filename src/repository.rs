use candid::Principal;
use fqdn::FQDN;
use mockall::automock;
use thiserror::Error;
use trait_async::trait_async;

use crate::{
    task::{InputTask, ScheduledTask, TaskKind, TaskResult},
    time::UtcTimestamp,
};

#[derive(Debug, Clone, Default)]
pub struct DomainEntry {
    pub task: Option<TaskKind>,
    pub canister_id: Option<Principal>,
    pub created_at: UtcTimestamp,
    pub taken_at: Option<UtcTimestamp>,
    pub certificate: Option<Vec<u8>>,
    pub private_key: Option<Vec<u8>>,
    pub not_before: Option<UtcTimestamp>,
    pub not_after: Option<UtcTimestamp>,
}

impl DomainEntry {
    pub fn new(task: Option<TaskKind>, created_at: UtcTimestamp) -> Self {
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
    NonExistingTaskSubmitted(UtcTimestamp),
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
    /// Retrieves the timestamp of the last change accross all registration records.
    async fn get_last_change_time(&self) -> Result<UtcTimestamp, RepositoryError>;
    /// Fetches all registered domains with valid certificates.
    async fn all_registrations(&self) -> Result<Vec<RegisteredDomain>, RepositoryError>;
}
