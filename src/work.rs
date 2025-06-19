use std::{sync::Arc, time::Duration};

use tokio::{select, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use trait_async::trait_async;

use crate::{
    task::{Task, TaskError, TaskOutput, TaskStatus},
    task_manager::ManagesTasks,
};

const POLLING_INTERVAL_NO_TASKS: Duration = Duration::from_secs(10);
const TASK_EXECUTION_TIMEOUT: Duration = Duration::from_secs(15);

#[trait_async]
pub trait RunsTasks {
    async fn run(&self);
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
                                            let _ = task_manager.submit_result(result).await;
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
                            info!("No pending tasks found, sleeping {} sec ...", POLLING_INTERVAL_NO_TASKS.as_secs());
                            select! {
                                _ = token.cancelled() => {
                                    warn!("Worker was stopped ...");
                                    return;
                                }
                                _ = tokio::time::sleep(POLLING_INTERVAL_NO_TASKS) => {}
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
