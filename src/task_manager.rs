use trait_async::trait_async;

use crate::task::{Task, TaskError, TaskOutput};

#[trait_async]
pub trait ManagesTasks: Send + Sync {
    async fn fetch(&self) -> Result<Option<Task>, TaskError>;
    async fn submit_result(&self, task: TaskOutput) -> Result<(), TaskError>;
    async fn try_add(&self, task: Task) -> Result<(), TaskError>;
}

pub struct TaskManager {/* wrapper around canister */}

#[trait_async]
impl ManagesTasks for TaskManager {
    async fn fetch(&self) -> Result<Option<Task>, TaskError> {
        Ok(None)
    }

    async fn submit_result(&self, _task: TaskOutput) -> Result<(), TaskError> {
        Ok(())
    }

    async fn try_add(&self, _task: Task) -> Result<(), TaskError> {
        Ok(())
    }
}
