use std::str::FromStr;

use canister_api::{SubmitTaskError as ApiSubmitTaskError, TryAddTaskError as ApiTryAddTaskError};
use fqdn::FQDN;
use mockall::automock;
use strum::IntoStaticStr;
use thiserror::Error;
use trait_async::trait_async;

use crate::{
    traits::time::UtcTimestamp,
    types::{
        domain::{CustomDomain, DomainStatus, RegisteredDomain},
        task::{InputTask, ScheduledTask, TaskResult},
    },
};
use anyhow::anyhow;

pub type TaskId = UtcTimestamp;

#[derive(Debug, Error, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum RepositoryError {
    #[error("Another task is in progress for domain: {0}")]
    AnotherTaskInProgress(FQDN),
    #[error("Certificate already issued for domain: {0}")]
    CertificateAlreadyIssued(FQDN),
    #[error("Domain not found: {0}")]
    DomainNotFound(FQDN),
    #[error("Failed to submit result of a non-existing task with ID: {0}")]
    NonExistingTaskSubmitted(TaskId),
    #[error("Update task requires an existing certificate for domain: {0}")]
    MissingCertificateForUpdate(FQDN),
    #[error(transparent)]
    InternalError(#[from] anyhow::Error),
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
    async fn submit_task_result(&self, task_result: TaskResult) -> Result<(), RepositoryError>;
    /// Tries to submit a new task of certain kind for a domain.
    async fn try_add_task(&self, task: InputTask) -> Result<(), RepositoryError>;
    /// Retrieves the timestamp of the last change accross all registration records.
    async fn get_last_change_time(&self) -> Result<UtcTimestamp, RepositoryError>;
    /// Fetches all registered domains with valid certificates.
    async fn all_registrations(&self) -> Result<Vec<RegisteredDomain>, RepositoryError>;
    /// Fetches all registered domains (without certificates).
    async fn all_registered_domains(&self) -> Result<Vec<CustomDomain>, RepositoryError>;
}

// TODO: consider using string in RepositoryError instead of FQDN
impl From<ApiSubmitTaskError> for RepositoryError {
    fn from(err: ApiSubmitTaskError) -> Self {
        match err {
            ApiSubmitTaskError::DomainNotFound(domain) => {
                RepositoryError::DomainNotFound(FQDN::from_str(&domain).unwrap_or_default())
            }
            ApiSubmitTaskError::NonExistingTaskSubmitted(task_id) => {
                RepositoryError::NonExistingTaskSubmitted(task_id)
            }
            ApiSubmitTaskError::InternalError(err) => RepositoryError::InternalError(anyhow!(err)),
        }
    }
}

impl From<ApiTryAddTaskError> for RepositoryError {
    fn from(err: ApiTryAddTaskError) -> Self {
        match err {
            ApiTryAddTaskError::DomainNotFound(domain) => {
                RepositoryError::DomainNotFound(FQDN::from_str(&domain).unwrap_or_default())
            }
            ApiTryAddTaskError::AnotherTaskInProgress(domain) => {
                RepositoryError::AnotherTaskInProgress(FQDN::from_str(&domain).unwrap_or_default())
            }
            ApiTryAddTaskError::CertificateAlreadyIssued(domain) => {
                RepositoryError::CertificateAlreadyIssued(
                    FQDN::from_str(&domain).unwrap_or_default(),
                )
            }
            ApiTryAddTaskError::MissingCertificateForUpdate(domain) => {
                RepositoryError::MissingCertificateForUpdate(
                    FQDN::from_str(&domain).unwrap_or_default(),
                )
            }
            ApiTryAddTaskError::InternalError(err) => RepositoryError::InternalError(anyhow!(err)),
        }
    }
}
