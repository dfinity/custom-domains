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

#[trait_async]
#[automock]
pub trait Repository: Send + Sync {
    async fn get_domain(&self, domain: &FQDN) -> Result<Option<DomainEntry>, RepositoryError>;
    async fn fetch_next_task(&self) -> Result<Option<ScheduledTask>, RepositoryError>;
    async fn submit_task_result(&self, task: TaskResult) -> Result<(), RepositoryError>;
    async fn try_add_task(&self, task: InputTask) -> Result<(), RepositoryError>;
}
