use crate::{
    helpers::{format_error_chain, retry_async},
    metrics::WorkerMetrics,
    repository::Repository,
    task::{
        IssueCertificateOutput, ScheduledTask, TaskFailReason, TaskKind, TaskOutput, TaskResult,
    },
    time::UtcTimestamp,
    validation::ValidatesDomains,
};
use anyhow::{Context, bail};
use candid::Principal;
use derive_new::new;
use fqdn::FQDN;
use ic_bn_lib::tls::acme::{
    client::Client,
    instant_acme::{RevocationReason, RevocationRequest},
};
use pem::parse_many;
use rustls_pki_types::CertificateDer;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    select,
    time::{self, sleep},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use x509_parser::parse_x509_certificate;

/// How long to wait between polling attempts when no tasks are available.
const DEFAULT_POLLING_INTERVAL_NO_TASKS: Duration = Duration::from_secs(20);
/// Maximum time a worker is allowed to spend processing a single task.
const DEFAULT_TASK_TIMEOUT: Duration = Duration::from_secs(360);
/// Maximum time allowed to attempt submitting the result of a completed task.
const DEFAULT_TASK_SUBMIT_TIMEOUT: Duration = Duration::from_secs(60);
/// Interval to wait before retrying to submit a failed task result.
const DEFAULT_TASK_RESUBMIT_INTERVAL: Duration = Duration::from_secs(5);
/// Interval to wait before retrying to fetch a new task if the previous fetch failed.
const DEFAULT_TASK_FETCH_RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// The time window over which each worker's utilization is measured.
const WORKER_UTILIZATION_WINDOW: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, new)]
pub struct WorkerConfig {
    pub polling_interval_no_tasks: Duration,
    pub task_timeout: Duration,
    pub task_submit_timeout: Duration,
    pub task_resubmit_interval: Duration,
    pub task_fetch_retry_interval: Duration,
    pub worker_utilization_window: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        WorkerConfig::new(
            DEFAULT_POLLING_INTERVAL_NO_TASKS,
            DEFAULT_TASK_TIMEOUT,
            DEFAULT_TASK_SUBMIT_TIMEOUT,
            DEFAULT_TASK_RESUBMIT_INTERVAL,
            DEFAULT_TASK_FETCH_RETRY_INTERVAL,
            WORKER_UTILIZATION_WINDOW,
        )
    }
}

#[allow(clippy::too_many_arguments)]
#[derive(new)]
pub struct Worker {
    pub name: String,
    pub repository: Arc<dyn Repository>,
    pub validator: Arc<dyn ValidatesDomains>,
    pub acme_client: Arc<Client>,
    pub config: WorkerConfig,
    pub metrics: Arc<WorkerMetrics>,
    pub total_time_since_reset: Arc<AtomicU64>,
    pub active_time_since_reset: Arc<AtomicU64>,
    pub token: CancellationToken,
}

// Indicates that worker was stopped externally and it should stop running.
struct WorkerStopped;

impl Worker {
    pub async fn run(&self) {
        loop {
            let cycle_start = Instant::now();

            // Check for cancellation before proceeding
            if self.token.is_cancelled() {
                warn!("Worker {} stopped due to cancellation", self.name);
                return;
            }

            // Fetch and process the next pending task
            if let Err(_) = self.fetch_and_process_task().await {
                return;
            }

            let cycle_duration = cycle_start.elapsed().as_secs();
            self.total_time_since_reset
                .fetch_add(cycle_duration, Ordering::Relaxed);
            self.maybe_update_utilization_metric();
        }
    }

    /// Fetches the next task and processes it, returning whether the worker should continue running
    async fn fetch_and_process_task(&self) -> Result<(), WorkerStopped> {
        let repository = self.repository.clone();

        let task = match repository.fetch_next_task().await {
            Ok(task) => {
                self.metrics
                    .task_fetches
                    .with_label_values(&[self.name.as_str(), "success", ""])
                    .inc();
                task
            }
            Err(err) => {
                error!(
                    error = %err,
                    duration_secs = self.config.task_fetch_retry_interval.as_secs(),
                    "Failed to fetch pending task for worker {}, sleeping before retry",
                    self.name
                );
                self.metrics
                    .task_fetches
                    .with_label_values(&[self.name.as_str(), "failure", err.into()])
                    .inc();
                sleep(self.config.task_fetch_retry_interval).await;
                return Ok(());
            }
        };

        match task {
            Some(task) => self.process_task(task).await,
            None => self.handle_no_tasks().await,
        }
    }

    /// Processes a single task with execution and submission, returning whether the worker should continue running
    async fn process_task(&self, task: ScheduledTask) -> Result<(), WorkerStopped> {
        let task_start = Instant::now();

        // Execute the task with a timeout
        let task_result = select! {
            _ = self.token.cancelled() => {
                warn!("Worker {} stopped due to cancellation during task processing", self.name);
                return Err(WorkerStopped);
            }
            result = execute_with_timeout(
                self.config.task_timeout,
                task.clone(),
                self.acme_client.clone(),
                self.validator.clone(),
            ) => result
        };

        // Submit task result with retries
        self.submit_task_result(&task, task_result.clone()).await?;

        // Calculate task duration
        let task_duration = task_start.elapsed();
        let task_duration_secs = task_duration.as_secs();

        let execution_status = if task_result.output.is_some() {
            "success"
        } else {
            "failure"
        };
        let execution_failure = task_result
            .failure
            .as_ref()
            .map(|err| err.to_short_error())
            .unwrap_or("");

        // Update worker busy time for utilization metric
        self.active_time_since_reset
            .fetch_add(task_duration_secs, Ordering::Relaxed);

        // Update metrics
        self.metrics
            .task_executions
            .with_label_values(&[
                self.name.as_str(),
                task.kind.as_ref(),
                execution_status,
                execution_failure,
            ])
            .observe(task_duration.as_secs_f64());

        Ok(())
    }

    /// Submits the task result with retries, returning whether the worker should continue running
    async fn submit_task_result(
        &self,
        task: &ScheduledTask,
        task_result: TaskResult,
    ) -> Result<(), WorkerStopped> {
        let closure = || async {
            let repository = self.repository.clone();
            let task_result = task_result.clone();
            repository.submit_task_result(task_result).await
        };

        select! {
            _ = self.token.cancelled() => {
                warn!("Worker {} stopped due to cancellation during submission", self.name);
                return Err(WorkerStopped);
            }
            result = retry_async(
                None,
                None,
                self.config.task_submit_timeout,
                self.config.task_resubmit_interval,
                closure,
            ) => {
                let (attempt, status, failure) = match result {
                    Ok((attempt, _)) => (attempt.to_string(), "success", ""),
                    Err(err) => {
                        let attempts = err.attempts.to_string();
                        let error = format!(
                            "Failed to submit task result for worker={} after {attempts} attempts: {err:?}",
                            self.name,
                        );
                        error!(
                            domain = %task.domain,
                            task_kind = %task.kind,
                            duration_secs = self.config.task_submit_timeout.as_secs(),
                            error = %error,
                        );
                        (err.attempts.to_string(), "failure", err.last_error.into())
                    }
                };

                self.metrics
                    .task_submissions
                    .with_label_values(&[
                        self.name.as_str(),
                        task.kind.as_ref(),
                        status,
                        &attempt,
                        failure,
                    ])
                    .inc();
            }
        }

        Ok(())
    }

    /// Handles no available tasks, returning whether the worker should continue running
    async fn handle_no_tasks(&self) -> Result<(), WorkerStopped> {
        debug!(
            duration_secs = self.config.polling_interval_no_tasks.as_secs(),
            "No pending tasks found for worker {}, sleeping", self.name
        );

        select! {
            _ = self.token.cancelled() => {
                warn!("Worker {} stopped due to cancellation during idle", self.name);
                return Err(WorkerStopped);
            }
            _ = sleep(self.config.polling_interval_no_tasks) => {}
        }

        Ok(())
    }

    /// Updates the worker utilization metric if the window has elapsed
    fn maybe_update_utilization_metric(&self) {
        let total = self.total_time_since_reset.load(Ordering::Relaxed);

        if total < self.config.worker_utilization_window.as_secs() {
            return;
        }

        // Take values and reset
        let active = self.active_time_since_reset.swap(0, Ordering::Relaxed);
        let total = self.total_time_since_reset.swap(0, Ordering::Relaxed);

        let utilization = if total == 0 {
            0.0
        } else {
            ((active as f64 / total as f64) * 1000.0).round() / 10.0
        };

        debug!(
            worker = %self.name,
            active_secs = active,
            total_secs = total,
            utilization = utilization,
            "Worker utilization metric published"
        );

        self.metrics
            .worker_utilization
            .with_label_values(&[self.name.as_str()])
            .set(utilization);
    }
}

async fn execute_with_timeout(
    timeout: Duration,
    task: ScheduledTask,
    acme_client: Arc<Client>,
    validator: Arc<dyn ValidatesDomains>,
) -> TaskResult {
    let start = Instant::now();

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
        Ok(task_result) => task_result.with_duration(start.elapsed()),
        Err(_) => TaskResult::failure(
            domain.clone(),
            TaskFailReason::Timeout {
                duration_secs: timeout.as_secs(),
            },
            task.id,
        )
        .with_duration(start.elapsed()),
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
