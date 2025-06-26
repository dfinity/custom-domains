use derive_new::new;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Domain(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskName {
    Create,
    Renew,
    Update,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, new)]
pub struct Task {
    pub name: TaskName,
    pub domain_name: Domain,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TaskStatus {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, new)]
pub struct TaskResult {
    pub task: Task,
    pub status: TaskStatus,
    pub certificate: Option<Vec<u8>>,
}
