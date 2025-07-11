use std::str::FromStr;
use std::sync::Arc;

use derive_new::new;
use fqdn::FQDN;

use crate::api::models::{ApiError, RegistrationStatus};
use crate::repository::Repository;
use crate::task::{InputTask, TaskKind};

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
}

fn parse_domain(domain: &str) -> Result<FQDN, ApiError> {
    FQDN::from_str(domain).map_err(|_| ApiError::BadRequest(format!("Invalid domain: {domain}")))
}
