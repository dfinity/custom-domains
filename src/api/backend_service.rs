use std::str::FromStr;
use std::sync::Arc;

use derive_new::new;
use fqdn::FQDN;

use crate::api::models::{ApiError, RegistrationStatus, ValidationStatus};
use crate::repository::Repository;
use crate::task::{InputTask, TaskKind};
use crate::validation::Validator;

#[derive(Clone, new)]
pub struct BackendService {
    pub repository: Arc<dyn Repository>,
}

impl BackendService {
    pub async fn try_add_task(&self, domain: &str, kind: TaskKind) -> Result<(), ApiError> {
        let domain = parse_domain(domain)?;
        let task = InputTask::new(kind, domain.clone());
        self.repository
            .try_add_task(task)
            .await
            .map_err(|err| err.into())
    }

    pub async fn get_registration_status(
        &self,
        domain: &str,
    ) -> Result<RegistrationStatus, ApiError> {
        let domain = parse_domain(domain)?;
        match self.repository.get_domain(&domain).await {
            Ok(Some(entry)) => Ok(if entry.task.is_some() {
                RegistrationStatus::Processing
            } else {
                RegistrationStatus::Registered
            }),
            Ok(None) => Err(ApiError::NotFound(format!("Domain {domain} not found"))),
            Err(_) => Err(ApiError::InternalServerError("Internal error".into())),
        }
    }

    pub async fn validate_domain(&self, domain: &str) -> Result<ValidationStatus, ApiError> {
        let domain = parse_domain(domain)?;
        let validator = Validator::default();
        match validator.validate(&domain).await {
            Ok(_) => Ok(ValidationStatus::ValidationSucceeded),
            Err(err) => Ok(ValidationStatus::ValidationFailed(err.to_string())),
        }
    }
}

fn parse_domain(domain: &str) -> Result<FQDN, ApiError> {
    FQDN::from_str(domain).map_err(|_| ApiError::BadRequest(format!("Invalid domain: {domain}")))
}
