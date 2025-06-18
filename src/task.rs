use derive_new::new;
use thiserror::Error;
use trait_async::trait_async;

#[derive(Debug, Error)]
pub enum TaskError {}

#[derive(Debug, Clone)]
pub struct Domain(pub String);

#[derive(Debug, Clone)]
pub enum TaskName {
    Create,
    Renew,
    Update,
    Delete,
}

#[derive(Debug, Clone, new)]
pub struct Task {
    pub name: TaskName,
    pub domain_name: Domain,
    pub failures: u32,
}

#[derive(Debug, Clone)]
pub enum TaskStatus {
    Succeeded,
    TimedOut,
    Failed,
}

#[derive(Debug, Clone)]
pub struct TaskOutput {
    pub task: Task,
    pub status: TaskStatus,
}

#[trait_async]
pub trait ManagesTasks: Send + Sync {
    async fn fetch(&self) -> Result<Option<Task>, TaskError>;
    async fn submit_result(&self, task: TaskOutput) -> Result<(), TaskError>;
    async fn try_add(&self, task: Task) -> Result<(), TaskError>;
}
