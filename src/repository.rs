use candid::Principal;
use fqdn::FQDN;
use mockall::automock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use trait_async::trait_async;

use crate::{
    task::{InputTask, ScheduledTask, TaskFailReason, TaskKind, TaskResult},
    time::UtcTimestamp,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainEntry {
    pub task: Option<TaskKind>,
    pub last_fail_time: Option<UtcTimestamp>,
    pub last_failure_reason: Option<TaskFailReason>,
    pub failures_count: u32,
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
    #[error("Update task requires an existing certificate for domain: {0}")]
    MissingCertificateForUpdate(FQDN),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Processing,
    Registered,
    Failure(String),
}

#[derive(Debug, Clone)]
pub struct DomainStatus {
    pub domain: FQDN,
    pub canister_id: Option<Principal>,
    pub status: RegistrationStatus,
}

#[trait_async]
#[automock]
pub trait Repository: Send + Sync {
    // Retrieves domain status.
    async fn get_domain_status(
        &self,
        domain: &FQDN,
    ) -> Result<Option<DomainStatus>, RepositoryError>;
    /// Fetch next pending task for execution.
    async fn fetch_next_task(&self) -> Result<Option<ScheduledTask>, RepositoryError>;
    /// Submits task execution result.
    async fn submit_task_result(&self, task: TaskResult) -> Result<(), RepositoryError>;
    /// Tries to submit a new task of certain kind for a domain.
    async fn try_add_task(&self, task: InputTask) -> Result<(), RepositoryError>;
    /// Retrieves the timestamp of the last change accross all registration records.
    async fn get_last_change_time(&self) -> Result<UtcTimestamp, RepositoryError>;
    /// Fetches all registered domains with valid certificates.
    async fn all_registrations(&self) -> Result<Vec<RegisteredDomain>, RepositoryError>;
}
