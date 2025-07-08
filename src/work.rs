use std::{sync::Arc, time::Duration};

use anyhow::Context;
use derive_new::new;
use fqdn::FQDN;
use pem::parse_many;
use tokio::{select, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use x509_parser::parse_x509_certificate;

use crate::{
    acme::create_acme_client,
    crypto::{CertificateCrypto, Crypto},
    repository::Repository,
    task::{IssueCertificateOutput, ScheduledTask, TaskKind, TaskOutput, TaskResult, TaskStatus},
    time::Timestamp,
};

const POLLING_INTERVAL_NO_TASKS: Duration = Duration::from_secs(15);
const TASK_EXECUTION_TIMEOUT: Duration = Duration::from_secs(250);

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

async fn execute(task: ScheduledTask) -> anyhow::Result<TaskResult> {
    use crate::validation::Validator;

    let domain = task.domain;
    let task_id = task.id;

    info!(
        domain = %domain,
        task_execution = %task.kind,
    );

    match task.kind {
        TaskKind::Issue => {
            let validator = Validator::default();
            match validator.validate(&domain).await {
                Ok(_) => {
                    let output = issue_certificate(&domain).await?;
                    info!(
                            domain = %domain,
                            task_execution = %task.kind,
                            output = ?output
                    );
                    let result = TaskResult::new(domain, TaskStatus::Succeeded, output, task_id);
                    return Ok(result);
                }
                Err(err) => {
                    error!(
                        domain = %domain,
                        executing_task = %task.kind,
                        "validation failed: {err}",
                    );
                }
            }
            todo!();
        }
        TaskKind::Renew => {
            // ATM this task is the same as `Issue`
            let validator = Validator::default();
            match validator.validate(&domain).await {
                Ok(_) => {
                    let output = issue_certificate(&domain).await?;
                    info!(
                            domain = %domain,
                            task_execution = %task.kind,
                            output = ?output
                    );
                    let result = TaskResult::new(domain, TaskStatus::Succeeded, output, task_id);
                    return Ok(result);
                }
                Err(err) => {
                    error!(
                        domain = %domain,
                        executing_task = %task.kind,
                        "validation failed: {err}",
                    );
                }
            }
            todo!();
        }
        TaskKind::Update => todo!(),
        TaskKind::Delete => {
            // TODO: revoke certificate
            info!(
                domain = %domain,
                "deletion succeeded",
            );
            let result =
                TaskResult::new(domain, TaskStatus::Succeeded, TaskOutput::Delete, task_id);
            Ok(result)
        }
    }
}

async fn issue_certificate(domain: &FQDN) -> anyhow::Result<TaskOutput> {
    let domain = domain.to_string();
    // Initialize ACME client
    let acme_client = create_acme_client()
        .await
        .context("Failed to create ACME client")?;

    // Issue certificate
    let certificate = acme_client
        .issue(&vec![domain.clone()], None)
        .await
        .context(format!("Failed to issue certificate for domain={domain}"))?;

    // Parse certificate chain
    let pem_str =
        std::str::from_utf8(&certificate.cert).context("Certificate contains invalid UTF-8")?;

    let pems = parse_many(pem_str).context("Failed to parse PEM certificates")?;

    let Some(first_cert) = pems.first() else {
        anyhow::bail!("No certificates found in PEM chain");
    };

    // Extract validity period
    let (_, cert) = parse_x509_certificate(first_cert.contents())
        .context("Failed to parse X509 certificate")?;

    let validity = cert.validity();
    let not_before = validity.not_before.to_datetime().unix_timestamp() as Timestamp;
    let not_after = validity.not_after.to_datetime().unix_timestamp() as Timestamp;

    if not_after <= not_before {
        anyhow::bail!("Invalid certificate validity period: not_after <= not_before");
    }

    // TODO: do real encryption
    let crypt = Crypto::new();

    let cert_enc = crypt.encrypt(certificate.cert.as_slice())?;
    let priv_key_enc = crypt.encrypt(certificate.key.as_slice())?;

    Ok(TaskOutput::Issue(IssueCertificateOutput::new(
        cert_enc,
        priv_key_enc,
        not_before,
        not_after,
    )))
}
