use base::{
    traits::{repository::Repository, validation::ValidatesDomains},
    types::{
        domain::DomainStatus,
        task::{InputTask, TaskKind},
    },
};
use std::{str::FromStr, sync::Arc};

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
    pub async fn submit_task(&self, domain: &str, task: TaskKind) -> Result<Principal, ApiError> {
        let fqdn = parse_domain(domain)?;
        let canister_id = self.validator.validate(&fqdn).await?;
        let task = InputTask::new(task, fqdn);
        match self.repository.try_add_task(task).await {
            Ok(()) => Ok(canister_id),
            Err(err) => Err(err.into()),
        }
    }

    /// Validates domain can be deleted and submits a delete task.
    pub async fn submit_delete_task(&self, domain: &str) -> Result<(), ApiError> {
        let fqdn = parse_domain(domain)?;
        self.validator.validate_deletion(&fqdn).await?;
        let task = InputTask::new(TaskKind::Delete, fqdn);
        match self.repository.try_add_task(task).await {
            Ok(()) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Retrieves the current status of a domain registration.
    pub async fn get_domain_status(&self, domain: &str) -> Result<DomainStatus, ApiError> {
        let fqdn = parse_domain(domain)?;
        match self.repository.get_domain_status(&fqdn).await {
            Ok(Some(entry)) => Ok(entry),
            Ok(None) => Err(ApiError::NotFound {
                details: format!("Domain {domain} not found"),
            }),
            Err(_) => Err(ApiError::InternalServerError {
                details: "".to_string(),
            }),
        }
    }

    /// Validates a domain is eligible for registration without submitting a task.
    pub async fn validate(&self, domain: &str) -> Result<(Principal, ValidationStatus), ApiError> {
        let fqdn = parse_domain(domain)?;
        match self.validator.validate(&fqdn).await {
            Ok(canister_id) => Ok((canister_id, ValidationStatus::Valid)),
            Err(err) => Err(ApiError::UnprocessableEntity {
                details: err.to_string(),
            }),
        }
    }
}

/// Parses a domain string into a validated FQDN.
fn parse_domain(domain: &str) -> Result<FQDN, ApiError> {
    FQDN::from_str(domain).map_err(|_| ApiError::BadRequest {
        details: format!("Invalid domain: {domain}"),
    })
}
