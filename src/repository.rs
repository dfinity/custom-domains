use mockall::automock;
use serde::Serialize;
use thiserror::Error;
use trait_async::trait_async;

use crate::task::{Domain, Task, TaskOutput};

#[derive(Serialize)]
pub enum RegistrationStatus {
    Submitted,
    Processing,
    Registered,
}

pub struct DomainEntry {
    pub domain: Domain,
    pub status: RegistrationStatus,
}

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("Task already created")]
    TaskAlreadyCreated,
}

#[trait_async]
#[automock]
pub trait Repository: Send + Sync {
    async fn get_entry(&self, domain: Domain) -> Result<Option<DomainEntry>, RepositoryError>;
    async fn fetch_task(&self) -> Result<Option<Task>, RepositoryError>;
    async fn submit_task_result(&self, task: TaskOutput) -> Result<(), RepositoryError>;
    async fn try_add_task(&self, task: Task) -> Result<(), RepositoryError>;
}
