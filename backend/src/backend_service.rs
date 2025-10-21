use base::{
    traits::{repository::Repository, validation::ValidatesDomains},
    types::{
        domain::DomainStatus,
        task::{InputTask, TaskKind},
    },
};
use std::sync::Arc;

use candid::Principal;
use derive_new::new;
use fqdn::FQDN;

use crate::models::{ApiError, ValidationStatus};

/// Backend service that orchestrates domain validation, task submission, and registration status retrieval.
///
/// This service acts as the logical layer between user and the repository (data storage).
#[derive(Clone, new)]
pub struct BackendService {
    /// Repository for storing domain data (e.g. certificates) and tasks
    pub repository: Arc<dyn Repository>,
    /// Domain validator for DNS and canister ownership checks
    pub validator: Arc<dyn ValidatesDomains>,
}

impl BackendService {
    /// Validates domain configuration and submits a task for further processing.
    pub async fn submit_task(&self, domain: FQDN, task: TaskKind) -> Result<Principal, ApiError> {
        let canister_id = self.validator.validate(&domain).await?;
        let task = InputTask::new(task, domain);

        match self.repository.try_add_task(task).await {
            Ok(()) => Ok(canister_id),
            Err(err) => Err(err.into()),
        }
    }

    /// Validates domain can be deleted and submits a delete task.
    pub async fn submit_delete_task(&self, domain: FQDN) -> Result<(), ApiError> {
        self.validator.validate_deletion(&domain).await?;
        let task = InputTask::new(TaskKind::Delete, domain);

        match self.repository.try_add_task(task).await {
            Ok(()) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Retrieves the current status of a domain registration.
    pub async fn get_domain_status(&self, domain: &FQDN) -> Result<DomainStatus, ApiError> {
        match self.repository.get_domain_status(domain).await {
            Ok(Some(entry)) => Ok(entry),
            Ok(None) => Err(ApiError::NotFound(format!("Domain {domain} not found"))),
            Err(_) => Err(ApiError::InternalServerError("".to_string())),
        }
    }

    /// Validates a domain is eligible for registration without submitting a task.
    pub async fn validate(&self, domain: &FQDN) -> Result<(Principal, ValidationStatus), ApiError> {
        match self.validator.validate(domain).await {
            Ok(canister_id) => Ok((canister_id, ValidationStatus::Valid)),
            Err(err) => Err(ApiError::UnprocessableEntity(err.to_string())),
        }
    }
}
