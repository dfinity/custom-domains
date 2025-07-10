use std::str::FromStr;
use std::sync::Arc;

use fqdn::FQDN;

use crate::api::models::{ApiError, RegistrationStatus, StatusResponse};
use crate::repository::{Repository, RepositoryError};
use crate::task::{InputTask, TaskKind};

#[derive(Clone)]
pub struct BackendService {
    repository: Arc<dyn Repository>,
}

impl BackendService {
    pub fn new(repository: Arc<dyn Repository>) -> Self {
        Self { repository }
    }

    fn parse_domain(&self, domain: &str) -> Result<FQDN, ApiError> {
        FQDN::from_str(domain)
            .map_err(|_| ApiError::BadRequest(format!("Invalid domain: {domain}")))
    }

    fn map_repository_error(&self, err: RepositoryError, domain: &str) -> ApiError {
        match err {
            RepositoryError::CertificateAlreadyIssued(_) => {
                ApiError::Conflict(format!("Certificate for {domain} already issued"))
            }
            RepositoryError::AnotherTaskInProgress(_) => ApiError::Conflict(err.to_string()),
            RepositoryError::DomainNotFound(_) => ApiError::NotFound("Domain not found".into()),
            _ => ApiError::InternalServerError("Internal error".into()),
        }
    }

    pub async fn add_task(&self, domain: &str, kind: TaskKind) -> Result<(), ApiError> {
        let fqdn = self.parse_domain(domain)?;
        let task = InputTask::new(kind, fqdn);
        self.repository
            .try_add_task(task)
            .await
            .map_err(|e| self.map_repository_error(e, domain))
    }

    pub async fn get_domain_status(&self, domain: &str) -> Result<StatusResponse, ApiError> {
        let fqdn = self.parse_domain(domain)?;
        match self.repository.get_domain(&fqdn).await {
            Ok(Some(entry)) => {
                let status = if entry.task.is_some() {
                    RegistrationStatus::Processing
                } else {
                    RegistrationStatus::Registered
                };
                Ok(StatusResponse { status })
            }
            Ok(None) => Err(ApiError::NotFound(format!("Domain {domain} not found"))),
            Err(_) => Err(ApiError::InternalServerError("Internal error".into())),
        }
    }
}
