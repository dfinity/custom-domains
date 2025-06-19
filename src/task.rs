use derive_new::new;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TaskError {}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq)]
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
