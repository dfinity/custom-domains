use derive_new::new;
use mockall::automock;
use thiserror::Error;
use trait_async::trait_async;

use crate::task::{Domain, Task, TaskName, TaskResult};

#[derive(Debug, Clone, new)]
pub struct DomainEntry {
    pub task: Option<TaskName>,
    pub certificate: Option<Vec<u8>>,
}

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("Task already exists")]
    TaskAlreadyExists,
    #[error("Domain not found")]
    DomainNotFound,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[trait_async]
#[automock]
pub trait Repository: Send + Sync {
    async fn get_domain(&self, domain: Domain) -> Result<Option<DomainEntry>, RepositoryError>;
    async fn fetch_next_task(&self) -> Result<Option<Task>, RepositoryError>;
    async fn submit_task_result(&self, task: TaskResult) -> Result<(), RepositoryError>;
    async fn try_add_task(&self, task: Task) -> Result<(), RepositoryError>;
}
