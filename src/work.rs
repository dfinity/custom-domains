use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use thiserror::Error;
use tokio::{select, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use trait_async::trait_async;

use crate::task::{Task, TaskOutput, TaskStatus};

const POLLING_INTERVAL_NO_TASKS: Duration = Duration::from_secs(15);
const TASK_EXECUTION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TASK_FAILURES: u32 = 10;

#[derive(Debug, Error)]
pub enum TaskError {}

#[trait_async]
pub trait RunsTasks {
    async fn run(&self);
}

#[trait_async]
pub trait ManagesTasks: Send + Sync {
    async fn fetch(&self) -> Result<Option<Task>, TaskError>;
    async fn submit(&self, task: TaskOutput) -> Result<(), TaskError>;
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

    async fn submit(&self, task: TaskOutput) -> Result<(), TaskError> {
        let mut lock = self.tasks.lock().unwrap();
        if task.task.failures < MAX_TASK_FAILURES {
            lock.push(task.clone().task);
        } else {
            debug!("task {task:?} failed too many times, dropping");
        }
        Ok(())
    }
}

pub struct Worker {
    pub task_manager: Arc<dyn ManagesTasks>,
    pub token: CancellationToken,
}

#[trait_async]
impl RunsTasks for Worker {
    async fn run(&self) {
        loop {
            let token = self.token.clone();
            let task_manager = self.task_manager.clone();

            tokio::select! {
                // Stop the worker upon cancellation
                _ = token.cancelled() => {
                    warn!("Worker was stopped during ...");
                    return;
                }
                // Poll for a pending task
                task = task_manager.fetch() => {
                    match task {
                        // Pending task found
                        Ok(Some(task)) => {
                            select! {
                                _ = token.cancelled() => {
                                    warn!("Worker was stopped ...");
                                    return;
                                }
                                _ = sleep(TASK_EXECUTION_TIMEOUT) => {
                                    error!("Task timed out");
                                    // TODO: submit some result
                                }
                                result = execute(task) => {
                                    match result {
                                        Ok(result) => {
                                            let _ = task_manager.submit(result).await;
                                        }
                                        Err(err) => {
                                            error!("Failed to execute task: {:?}", err);
                                        }
                                    }
                                }
                            }
                        }
                        // No pending tasks found
                        Ok(None) => {
                            select! {
                                _ = token.cancelled() => {
                                    warn!("Worker was stopped ...");
                                    return;
                                }
                                _ = tokio::time::sleep(POLLING_INTERVAL_NO_TASKS) => {
                                    info!("No pending tasks found, sleeping...");
                                }
                            }
                        }
                        // Unexpected error when fetching a task
                        Err(err) => {
                            error!("Failed to fetch pending task: {}", err);
                        }
                    }
                }
            }
        }
    }
}

async fn execute(mut task: Task) -> Result<TaskOutput, TaskError> {
    info!("start execution of task {:?} started", task);
    sleep(Duration::from_secs(10)).await;
    info!("end execution of task {:?} started", task);
    task.failures += 1;
    Ok(TaskOutput {
        status: TaskStatus::Failed,
        task,
    })
}
