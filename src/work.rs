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
use tracing::{error, info, warn};
use x509_parser::parse_x509_certificate;

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

#[allow(clippy::too_many_arguments)]
#[derive(new)]
pub struct Worker {
    pub name: String,
    pub repository: Arc<dyn Repository>,
    pub validator: Arc<dyn ValidatesDomains>,
    pub acme_client: Arc<Client>,
    pub config: WorkerConfig,
    pub metrics: Arc<WorkerMetrics>,
    pub active_time: Arc<AtomicU64>,
    pub total_time: Arc<AtomicU64>,
    pub token: CancellationToken,
}

impl Worker {
    pub async fn run(&self) {
        let worker_start = Instant::now();

        loop {
            // Update total runtime for worker utilization calculation
            self.total_time
                .store(worker_start.elapsed().as_secs(), Ordering::Relaxed);

            // Check for cancellation before proceeding
            if self.token.is_cancelled() {
                warn!("Worker {} stopped due to cancellation", self.name);
                return;
            }

            // Fetch and process the next task
            match self.fetch_and_process_task().await {
                Ok(continue_running) => {
                    if !continue_running {
                        return;
                    }
                }
                Err(err) => {
                    error!(error = %err, "Failed to fetch pending task for worker {}", self.name);
                    self.metrics
                        .task_fetches
                        .with_label_values(&[self.name.as_str(), "failure"])
                        .inc();
                    self.update_utilization();
                }
            }
        }
    }

    /// Fetches the next task and processes it, returning whether the worker should continue running
    async fn fetch_and_process_task(&self) -> anyhow::Result<bool> {
        let repository = self.repository.clone();
        let task = repository.fetch_next_task().await?;

        match task {
            Some(task) => {
                self.metrics
                    .task_fetches
                    .with_label_values(&[self.name.as_str(), "success"])
                    .inc();
                self.process_task(task).await
            }
            None => self.handle_no_tasks().await,
        }
    }

    /// Processes a single task with execution and submission
    async fn process_task(&self, task: ScheduledTask) -> anyhow::Result<bool> {
        let task_start = Instant::now();

        // Execute the task with a timeout
        let task_result = select! {
            _ = self.token.cancelled() => {
                warn!("Worker {} stopped due to cancellation during task processing", self.name);
                return Ok(false);
            }
            result = execute_with_timeout(
                self.config.task_timeout,
                task.clone(),
                self.acme_client.clone(),
                self.validator.clone(),
            ) => result
        };

        // Update worker's active time
        let task_duration = task_start.elapsed().as_secs();
        self.active_time.fetch_add(task_duration, Ordering::Relaxed);

        // Submit task result
        let submission_result = self.submit_task_result(&task, task_result.clone()).await;

        // Update metrics
        self.update_task_metrics(&task, &task_result, &submission_result);
        self.update_utilization();

        Ok(true)
    }

    /// Submits the task result with retries
    async fn submit_task_result(
        &self,
        task: &ScheduledTask,
        task_result: TaskResult,
    ) -> (String, &'static str) {
        let closure = || async {
            let repository = self.repository.clone();
            let task_result = task_result.clone();
            repository
                .submit_task_result(task_result)
                .await
                .map_err(|err| anyhow!(err))
        };

        match retry_async(
            None,
            None,
            self.config.task_submit_timeout,
            self.config.task_resubmit_interval,
            closure,
        )
        .await
        {
            Ok((attempt, _)) => (attempt.to_string(), "success"),
            Err((attempt, err)) => {
                error!(
                    domain = %task.domain,
                    task_kind = %task.kind,
                    duration_secs = self.config.task_submit_timeout.as_secs(),
                    error = %err,
                    "Failed to submit task result for worker {} after retries", self.name
                );
                (attempt.to_string(), "failure")
            }
        }
    }

    /// Updates metrics for task execution and submission
    fn update_task_metrics(
        &self,
        task: &ScheduledTask,
        task_result: &TaskResult,
        submission_result: &(String, &'static str),
    ) {
        let task_kind = task.kind.as_ref();
        let execution_status = if task_result.output.is_some() {
            "success"
        } else {
            "failure"
        };
        let execution_duration = task_result.duration.as_secs_f64();
        let (attempt, submission_status) = submission_result;

        let execution_failure = task_result
            .failure
            .as_ref()
            .map(|err| err.to_short_error())
            .unwrap_or("");

        self.metrics
            .task_executions
            .with_label_values(&[
                self.name.as_str(),
                task_kind,
                execution_status,
                execution_failure,
            ])
            .observe(execution_duration);

        self.metrics
            .task_submissions
            .with_label_values(&[self.name.as_str(), task_kind, submission_status, attempt])
            .inc();
    }

    /// Handles no available tasks, return true if worker should continue running
    async fn handle_no_tasks(&self) -> anyhow::Result<bool> {
        info!(
            duration_secs = self.config.polling_interval_no_tasks.as_secs(),
            "No pending tasks found for worker {}, sleeping", self.name
        );

        select! {
            _ = self.token.cancelled() => {
                warn!("Worker {} stopped due to cancellation during idle", self.name);
                Ok(false)
            }
            _ = sleep(self.config.polling_interval_no_tasks) => {
                self.metrics.task_fetches.with_label_values(&[self.name.as_str(), "success"]).inc();
                self.update_utilization();
                Ok(true)
            }
        }
    }

    /// Updates the worker utilization metric
    fn update_utilization(&self) {
        let active = self.active_time.load(Ordering::Relaxed) as f64;
        let total = self.total_time.load(Ordering::Relaxed) as f64;

        let utilization = if total > 0.0 {
            (active / total) * 100.0
        } else {
            0.0
        };

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
