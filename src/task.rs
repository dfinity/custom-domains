use derive_new::new;

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
