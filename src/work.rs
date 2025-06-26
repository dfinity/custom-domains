use std::{sync::Arc, time::Duration};

use anyhow::Error;
use derive_new::new;
use tokio::{select, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    acme::create_acme_client,
    repository::Repository,
    task::{Task, TaskName, TaskResult, TaskStatus},
};

const POLLING_INTERVAL_NO_TASKS: Duration = Duration::from_secs(15);
const TASK_EXECUTION_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(new)]
pub struct Worker {
    pub state: Arc<dyn Repository>,
    pub token: CancellationToken,
}

impl Worker {
    pub async fn run(&self) {
        loop {
            let token = self.token.clone();
            let task_manager = self.state.clone();

            tokio::select! {
                // Stop the worker upon cancellation
                _ = token.cancelled() => {
                    warn!("Worker was stopped during ...");
                    return;
                }
                // Poll for a pending task
                task = task_manager.fetch_next_task() => {
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
                                            let _ = task_manager.submit_task_result(result).await;
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

async fn execute(task: Task) -> Result<TaskResult, Error> {
    use crate::validation::Validator;

    let domain: &str = &task.domain_name.0;

    info!("executing task_name={:?} for domain {domain}", task.name);

    match task.name {
        TaskName::Create => {
            let validator = Validator::default();
            match validator.validate(domain).await {
                Ok(canister_id) => {
                    // TODO: try to delete challenge records upfront
                    sleep(Duration::from_secs(10)).await;
                    info!("validation for domain {domain} and canister {canister_id} succeeded");
                    let acme_client = create_acme_client().await?;
                    let certificate = acme_client.issue(&vec![domain.into()], None).await?;
                    info!(
                        "successfully obtained certificate for domain={domain}, certificate={:?}",
                        certificate.cert
                    );
                    let result = TaskResult::new(
                        task.clone(),
                        TaskStatus::Succeeded,
                        Some(certificate.cert),
                    );
                    return Ok(result);
                }
                Err(err) => {
                    error!("validation of domain {domain} failed: {err}");
                }
            }
            todo!();
        }
        TaskName::Renew => todo!(),
        TaskName::Update => todo!(),
        TaskName::Delete => {
            // TODO: revoke certificate
            sleep(Duration::from_secs(5)).await;
            info!("deletion of domain {domain} succeeded");
            let result = TaskResult::new(task.clone(), TaskStatus::Succeeded, None);
            Ok(result)
        }
    }
}
