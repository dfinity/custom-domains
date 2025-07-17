use std::{sync::Arc, time::Duration};

use anyhow::Context;
use candid::Principal;
use derive_new::new;
use fqdn::FQDN;
use ic_bn_lib::tls::acme::{
    client::Client,
    instant_acme::{RevocationReason, RevocationRequest},
};
use pem::parse_many;
use rustls_pki_types::CertificateDer;
use tokio::{select, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use x509_parser::parse_x509_certificate;

use crate::{
    repository::Repository,
    task::{
        IssueCertificateOutput, ScheduledTask, TaskFailReason, TaskKind, TaskOutput, TaskResult,
    },
    time::UtcTimestamp,
    validation::ValidatesDomains,
};

const DEFAULT_POLLING_INTERVAL_NO_TASKS: Duration = Duration::from_secs(20);
const DEFAULT_TASK_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, new)]
pub struct WorkerConfig {
    pub polling_interval_no_tasks: Duration,
    pub task_timeout: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        WorkerConfig::new(DEFAULT_POLLING_INTERVAL_NO_TASKS, DEFAULT_TASK_TIMEOUT)
    }
}

#[derive(new)]
pub struct Worker {
    pub state: Arc<dyn Repository>,
    pub validator: Arc<dyn ValidatesDomains>,
    pub acme_client: Arc<Client>,
    pub token: CancellationToken,
    pub config: WorkerConfig,
}

impl Worker {
    pub async fn run(&self) {
        let idle_interval = self.config.polling_interval_no_tasks;
        let task_timeout = self.config.task_timeout;

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
                                _ = sleep(task_timeout) => {
                                    error!("Task timed out");
                                    // TODO: submit some result
                                }
                                result = execute(task, self.acme_client.clone(), self.validator.clone()) => {
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
                            info!("No pending tasks found, sleeping {} sec ...", idle_interval.as_secs());
                            select! {
                                _ = token.cancelled() => {
                                    warn!("Worker was stopped ...");
                                    return;
                                }
                                _ = tokio::time::sleep(idle_interval) => {}
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

async fn execute(
    task: ScheduledTask,
    acme_client: Arc<Client>,
    validator: Arc<dyn ValidatesDomains>,
) -> anyhow::Result<TaskResult> {
    let domain = task.domain;
    let task_id = task.id;

    info!(domain = %domain, task_execution = %task.kind);

    match task.kind {
        TaskKind::Issue => match validator.validate(&domain).await {
            Ok(canister_id) => {
                let output = issue_certificate(&domain, canister_id, acme_client).await?;
                info!(domain = %domain, task_execution = %task.kind, output = ?output);
                TaskResult::new(domain, Some(output), None, task_id)
            }
            Err(err) => {
                error!(domain = %domain, executing_task = %task.kind, "validation failed: {err}");
                TaskResult::new(
                    domain,
                    None,
                    Some(TaskFailReason::ValidationFailed(err.to_string())),
                    task_id,
                )
            }
        },
        TaskKind::Renew => {
            // ATM this task is the same as `Issue`
            match validator.validate(&domain).await {
                Ok(canister_id) => {
                    let output = issue_certificate(&domain, canister_id, acme_client).await?;
                    info!(domain = %domain, task_execution = %task.kind, output = ?output);
                    TaskResult::new(domain, Some(output), None, task_id)
                }
                Err(err) => {
                    error!(domain = %domain, executing_task = %task.kind, "validation failed: {err}");
                    TaskResult::new(
                        domain,
                        None,
                        Some(TaskFailReason::ValidationFailed(err.to_string())),
                        task_id,
                    )
                }
            }
        }
        TaskKind::Update => match validator.validate(&domain).await {
            Ok(canister_id) => {
                let output = TaskOutput::Update(canister_id);
                info!(domain = %domain, task_execution = %task.kind, output = ?output);
                TaskResult::new(domain, Some(output), None, task_id)
            }
            Err(err) => {
                error!(domain = %domain, executing_task = %task.kind, "validation failed: {err}");
                TaskResult::new(
                    domain,
                    None,
                    Some(TaskFailReason::ValidationFailed(err.to_string())),
                    task_id,
                )
            }
        },
        TaskKind::Delete => match validator.validate_deletion(&domain).await {
            Ok(()) => {
                // Revoke certificate if present
                if let Some(certificate) = task.certificate {
                    // Parse certificate chain
                    let pem_str = std::str::from_utf8(&certificate)
                        .context("Certificate contains invalid UTF-8")?;

                    let pems = parse_many(pem_str).context("Failed to parse PEM certificates")?;

                    let Some(first_cert) = pems.first() else {
                        anyhow::bail!("No certificates found in PEM chain");
                    };

                    // Only the end-entity certificate is needed to initiate revocation
                    let cert_der = CertificateDer::from(first_cert.contents().to_vec());

                    let revocation_request = RevocationRequest {
                        certificate: &cert_der,
                        reason: Some(RevocationReason::CessationOfOperation),
                    };

                    acme_client
                        .revoke(revocation_request)
                        .await
                        .context("revocation failed")?;

                    info!(domain = %domain, "revocation succeeded");
                }

                let task_output = TaskOutput::Delete;

                info!(domain = %domain, task_execution = %task.kind, output = ?task_output);

                TaskResult::new(domain, Some(task_output), None, task_id)
            }
            Err(err) => {
                error!(domain = %domain, executing_task = %task.kind, "delete validation failed: {err}");
                TaskResult::new(
                    domain,
                    None,
                    Some(TaskFailReason::ValidationFailed(err.to_string())),
                    task_id,
                )
            }
        },
    }
}

async fn issue_certificate(
    domain: &FQDN,
    canister_id: Principal,
    acme_client: Arc<Client>,
) -> anyhow::Result<TaskOutput> {
    let domain = domain.to_string();

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
    let not_before = validity.not_before.to_datetime().unix_timestamp() as UtcTimestamp;
    let not_after = validity.not_after.to_datetime().unix_timestamp() as UtcTimestamp;

    if not_after <= not_before {
        anyhow::bail!("Invalid certificate validity period: not_after <= not_before");
    }

    Ok(TaskOutput::Issue(IssueCertificateOutput::new(
        canister_id,
        certificate.cert,
        certificate.key,
        not_before,
        not_after,
    )))
}
