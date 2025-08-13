use std::str::FromStr;

use canister_api::{
    FetchTaskError as ApiFetchTaskError, GetDomainStatusError as ApiGetDomainStatusError,
    GetLastChangeTimeError as ApiGetLastChangeTimeError,
    ListCertificatesPageError as ApiListCertificatesPageError,
    SubmitTaskError as ApiSubmitTaskError, TryAddTaskError as ApiTryAddTaskError,
};
use fqdn::FQDN;
use mockall::automock;
use strum::IntoStaticStr;
use thiserror::Error;
use trait_async::trait_async;

use crate::{
    traits::time::UtcTimestamp,
    types::{
        domain::{DomainStatus, RegisteredDomain},
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
    /// Retrieves domain status.
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
}

impl TryFrom<ApiSubmitTaskError> for RepositoryError {
    type Error = anyhow::Error;

    fn try_from(err: ApiSubmitTaskError) -> Result<Self, Self::Error> {
        match err {
            ApiSubmitTaskError::DomainNotFound(domain) => {
                Ok(RepositoryError::DomainNotFound(FQDN::from_str(&domain)?))
            }
            ApiSubmitTaskError::NonExistingTaskSubmitted(task_id) => {
                Ok(RepositoryError::NonExistingTaskSubmitted(task_id))
            }
            ApiSubmitTaskError::InternalError(err) => {
                Ok(RepositoryError::InternalError(anyhow!(err)))
            }
        }
    }
}

impl TryFrom<ApiTryAddTaskError> for RepositoryError {
    type Error = anyhow::Error;

    fn try_from(err: ApiTryAddTaskError) -> Result<Self, Self::Error> {
        match err {
            ApiTryAddTaskError::DomainNotFound(domain) => {
                Ok(RepositoryError::DomainNotFound(FQDN::from_str(&domain)?))
            }
            ApiTryAddTaskError::AnotherTaskInProgress(domain) => Ok(
                RepositoryError::AnotherTaskInProgress(FQDN::from_str(&domain)?),
            ),
            ApiTryAddTaskError::CertificateAlreadyIssued(domain) => Ok(
                RepositoryError::CertificateAlreadyIssued(FQDN::from_str(&domain)?),
            ),
            ApiTryAddTaskError::MissingCertificateForUpdate(domain) => Ok(
                RepositoryError::MissingCertificateForUpdate(FQDN::from_str(&domain)?),
            ),
            ApiTryAddTaskError::InternalError(err) => {
                Ok(RepositoryError::InternalError(anyhow!(err)))
            }
        }
    }
}

impl TryFrom<ApiGetDomainStatusError> for RepositoryError {
    type Error = anyhow::Error;

    fn try_from(err: ApiGetDomainStatusError) -> Result<Self, Self::Error> {
        match err {
            ApiGetDomainStatusError::InternalError(err) => {
                Ok(RepositoryError::InternalError(anyhow!(err)))
            }
        }
    }
}

impl TryFrom<ApiFetchTaskError> for RepositoryError {
    type Error = anyhow::Error;

    fn try_from(err: ApiFetchTaskError) -> Result<Self, Self::Error> {
        match err {
            ApiFetchTaskError::InternalError(err) => {
                Ok(RepositoryError::InternalError(anyhow!(err)))
            }
        }
    }
}

impl TryFrom<ApiGetLastChangeTimeError> for RepositoryError {
    type Error = anyhow::Error;

    fn try_from(err: ApiGetLastChangeTimeError) -> Result<Self, Self::Error> {
        match err {
            ApiGetLastChangeTimeError::InternalError(err) => {
                Ok(RepositoryError::InternalError(anyhow!(err)))
            }
        }
    }
}

impl TryFrom<ApiListCertificatesPageError> for RepositoryError {
    type Error = anyhow::Error;

    fn try_from(err: ApiListCertificatesPageError) -> Result<Self, Self::Error> {
        match err {
            ApiListCertificatesPageError::InternalError(err) => {
                Ok(RepositoryError::InternalError(anyhow!(err)))
            }
        }
    }
}
