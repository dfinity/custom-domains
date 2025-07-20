use std::{sync::Arc, time::Duration};

use anyhow::{Context, anyhow, bail};
use candid::Principal;
use derive_new::new;
use fqdn::FQDN;
use ic_bn_lib::tls::acme::{
    client::Client,
    instant_acme::{RevocationReason, RevocationRequest},
};
use pem::parse_many;
use rustls_pki_types::CertificateDer;
use tokio::{
    select,
    time::{self},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use x509_parser::parse_x509_certificate;

use crate::{
    helpers::{format_error_chain, retry_async},
    repository::Repository,
    task::{
        IssueCertificateOutput, ScheduledTask, TaskFailReason, TaskKind, TaskOutput, TaskResult,
    },
    time::UtcTimestamp,
    validation::ValidatesDomains,
};

const DEFAULT_POLLING_INTERVAL_NO_TASKS: Duration = Duration::from_secs(20);
const DEFAULT_TASK_TIMEOUT: Duration = Duration::from_secs(360);
const DEFAULT_TASK_SUBMIT_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_TASK_RESUBMIT_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, new)]
pub struct WorkerConfig {
    pub polling_interval_no_tasks: Duration,
    pub task_timeout: Duration,
    pub task_submit_timeout: Duration,
    pub task_resubmit_interval: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        WorkerConfig::new(
            DEFAULT_POLLING_INTERVAL_NO_TASKS,
            DEFAULT_TASK_TIMEOUT,
            DEFAULT_TASK_SUBMIT_TIMEOUT,
            DEFAULT_TASK_RESUBMIT_INTERVAL,
        )
    }
}

#[derive(new)]
pub struct Worker {
    pub repository: Arc<dyn Repository>,
    pub validator: Arc<dyn ValidatesDomains>,
    pub acme_client: Arc<Client>,
    pub token: CancellationToken,
    pub config: WorkerConfig,
}

impl Worker {
    pub async fn run(&self) {
        let idle_interval = self.config.polling_interval_no_tasks;
        let task_timeout = self.config.task_timeout;
        let submit_timeout = self.config.task_submit_timeout;
        let resubmit_interval = self.config.task_resubmit_interval;

        loop {
            let token = self.token.clone();
            let repository = self.repository.clone();

            tokio::select! {
                // Stop the worker upon cancellation
                _ = token.cancelled() => {
                    warn!("Worker stopped due to cancellation");
                    return;
                }
                // Poll for a pending task
                task = repository.fetch_next_task() => {
                    match task {
                        // Pending task found
                        Ok(Some(task)) => {
                            select! {
                                _ = token.cancelled() => {
                                    warn!("Worker stopped due to cancellation");
                                    return;
                                }
                                task_result = execute_with_timeout(task_timeout, task.clone(), self.acme_client.clone(), self.validator.clone()) => {
                                    let closure = || async {
                                        let repository = repository.clone();
                                        let task_result = task_result.clone();
                                        repository.submit_task_result(task_result).await.map_err(|err| anyhow!(err))
                                    };
                                    if let Err(err) = retry_async(None, None, submit_timeout, resubmit_interval, closure).await {
                                        error!(
                                            domain = %task.domain,
                                            task_kind = %task.kind,
                                            duration_secs = submit_timeout.as_secs(),
                                            error = %err,
                                            "Failed to submit task result after retries"
                                        );
                                    }
                                }
                            }
                        }
                        // No pending tasks found
                        Ok(None) => {
                            info!(
                                duration_secs = idle_interval.as_secs(),
                                "No pending tasks found, sleeping"
                            );
                            select! {
                                _ = token.cancelled() => {
                                    warn!("Worker stopped due to cancellation");
                                    return;
                                }
                                _ = tokio::time::sleep(idle_interval) => {}
                            }
                        }
                        // Unexpected error when fetching a task
                        Err(err) => {
                            error!(
                                error = %err,
                                "Failed to fetch pending task"
                            );
                        }
                    }
                }
            }
        }
    }
}

async fn execute_with_timeout(
    timeout: Duration,
    task: ScheduledTask,
    acme_client: Arc<Client>,
    validator: Arc<dyn ValidatesDomains>,
) -> TaskResult {
    let domain = task.domain;
    let task_id = task.id;

    info!(
        domain = %domain,
        task_kind = %task.kind,
        "Task execution started"
    );

    let task_result = match time::timeout(timeout, async {
        let domain = domain.clone();

        match task.kind {
            TaskKind::Issue | TaskKind::Renew => {
                issue_task(domain, validator, acme_client, task_id).await
            }
            TaskKind::Update => update_task(domain, validator, task_id).await,
            TaskKind::Delete => {
                delete_task(domain, validator, acme_client, task_id, task.certificate).await
            }
        }
    })
    .await
    {
        Ok(task_result) => task_result,
        Err(_) => TaskResult::failure(
            domain.clone(),
            TaskFailReason::Timeout {
                duration_secs: timeout.as_secs(),
            },
            task.id,
        ),
    };

    if task_result.output.is_some() {
        info!(
            domain = %domain,
            task_kind = %task.kind,
            "Task execution succeeded"
        );
    } else if let Some(ref err) = task_result.failure {
        error!(
            domain = %domain,
            task_kind = %task.kind,
            error = %err,
            "Task execution failed"
        );
    }

    task_result
}

async fn issue_task(
    domain: FQDN,
    validator: Arc<dyn ValidatesDomains>,
    acme_client: Arc<Client>,
    task_id: UtcTimestamp,
) -> TaskResult {
    match validator.validate(&domain).await {
        Ok(canister_id) => match issue_certificate(&domain, canister_id, acme_client).await {
            Ok(output) => TaskResult::success(domain.clone(), output, task_id),
            Err(err) => TaskResult::failure(
                domain,
                TaskFailReason::GenericFailure(format_error_chain(&err)),
                task_id,
            ),
        },
        Err(err) => TaskResult::failure(
            domain,
            TaskFailReason::ValidationFailed(err.to_string()),
            task_id,
        ),
    }
}

async fn issue_certificate(
    domain: &FQDN,
    canister_id: Principal,
    acme_client: Arc<Client>,
) -> anyhow::Result<TaskOutput> {
    let domain_str = domain.to_string();

    // Issue certificate
    let certificate = acme_client
        .issue(&vec![domain_str.clone()], None)
        .await
        .with_context(|| "Certificate issuance failed")?;

    // Parse certificate chain
    let pem_str = std::str::from_utf8(&certificate.cert)
        .with_context(|| "Certificate contains invalid UTF-8")?;

    let pems = parse_many(pem_str).with_context(|| "Failed to parse PEM certificates")?;

    let Some(first_cert) = pems.first() else {
        bail!("No certificates found in PEM chain");
    };

    // Extract validity period
    let (_, cert) = parse_x509_certificate(first_cert.contents())
        .with_context(|| "Failed to parse X509 certificate")?;

    let validity = cert.validity();
    let not_before = validity.not_before.to_datetime().unix_timestamp() as UtcTimestamp;
    let not_after = validity.not_after.to_datetime().unix_timestamp() as UtcTimestamp;

    if not_after <= not_before {
        bail!("Invalid certificate validity period: not_after <= not_before");
    }

    Ok(TaskOutput::Issue(IssueCertificateOutput::new(
        canister_id,
        certificate.cert,
        certificate.key,
        not_before,
        not_after,
    )))
}

async fn update_task(
    domain: FQDN,
    validator: Arc<dyn ValidatesDomains>,
    task_id: UtcTimestamp,
) -> TaskResult {
    match validator.validate(&domain).await {
        Ok(canister_id) => TaskResult::success(domain, TaskOutput::Update(canister_id), task_id),
        Err(err) => TaskResult::failure(
            domain,
            TaskFailReason::ValidationFailed(err.to_string()),
            task_id,
        ),
    }
}

async fn delete_task(
    domain: FQDN,
    validator: Arc<dyn ValidatesDomains>,
    acme_client: Arc<Client>,
    task_id: UtcTimestamp,
    certificate: Option<Vec<u8>>,
) -> TaskResult {
    match validator.validate_deletion(&domain).await {
        Ok(()) => {
            // Revoke certificate if present
            if let Some(certificate) = certificate {
                match revoke_certificate(certificate.as_slice(), acme_client).await {
                    Ok(()) => {
                        return TaskResult::success(domain.clone(), TaskOutput::Delete, task_id);
                    }
                    Err(err) => {
                        return TaskResult::failure(
                            domain,
                            TaskFailReason::GenericFailure(format_error_chain(&err)),
                            task_id,
                        );
                    }
                }
            }
            TaskResult::success(domain.clone(), TaskOutput::Delete, task_id)
        }
        Err(err) => TaskResult::failure(
            domain,
            TaskFailReason::ValidationFailed(err.to_string()),
            task_id,
        ),
    }
}

async fn revoke_certificate(certificate: &[u8], acme_client: Arc<Client>) -> anyhow::Result<()> {
    // Parse certificate chain
    let pem_str =
        std::str::from_utf8(certificate).with_context(|| "Certificate contains invalid UTF-8")?;

    let pems = parse_many(pem_str).with_context(|| "Failed to parse PEM certificates")?;

    let Some(first_cert) = pems.first() else {
        bail!("No certificates found in PEM chain");
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
        .with_context(|| "revocation failed")?;

    Ok(())
}
