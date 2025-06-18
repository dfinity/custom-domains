use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use derive_new::new;
use thiserror::Error;
use tokio::time::sleep;
use tracing::debug;
use trait_async::trait_async;

const MAX_TASK_FAILURES: u32 = 10;

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

pub struct TaskManager {
    pub tasks: Arc<Mutex<Vec<Task>>>,
}

#[trait_async]
impl ManagesTasks for TaskManager {
    async fn fetch(&self) -> Result<Option<Task>, TaskError> {
        let task = {
            let mut lock = self.tasks.lock().unwrap();
            let task = lock.pop();
            debug!("fetched task is {task:?}");
            task
        };

        sleep(Duration::from_secs(20)).await;
        Ok(task)
    }

    async fn submit_result(&self, task: TaskOutput) -> Result<(), TaskError> {
        let mut lock = self.tasks.lock().unwrap();
        if task.task.failures < MAX_TASK_FAILURES {
            lock.push(task.clone().task);
        } else {
            debug!("task {task:?} failed too many times, dropping");
        }
        Ok(())
    }

    async fn try_add(&self, _task: Task) -> Result<(), TaskError> {
        Ok(())
    }
}
