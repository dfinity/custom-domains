use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{bail, Context};
use candid::Principal;
use derive_new::new;
use fqdn::FQDN;
use ic_bn_lib::{
    rustls::pki_types::CertificateDer,
    tls::acme::{
        client::AcmeCertificateClient,
        instant_acme::{RevocationReason, RevocationRequest},
    },
};
use pem::parse_many;
use prometheus::{
    register_gauge_vec_with_registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, GaugeVec, HistogramVec, IntCounterVec, Registry,
};
use tokio::{
    select,
    time::{self, sleep},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, error, info, warn};
use x509_parser::{parse_x509_certificate, prelude::GeneralName};

use crate::{
    helpers::{format_error_chain, retry_async},
    traits::{repository::Repository, time::UtcTimestamp, validation::ValidatesDomains},
    types::task::{
        IssueCertificateOutput, ScheduledTask, TaskFailReason, TaskKind, TaskOutput, TaskResult,
    },
};

pub const TASK_DURATION_BUCKETS: &[f64] = &[5.0, 30.0, 60.0, 90.0, 120.0, 180.0, 300.0, 400.0];

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
/// Delay before revoking an old certificate after a successful certificate renewal.
const CERT_REVOCATION_DELAY_AFTER_RENEWAL: Duration = Duration::from_secs(10 * 60);

/// Configuration settings for worker behavior and timeouts.
#[derive(Debug, Clone, new)]
pub struct WorkerConfig {
    /// How long to wait between polling attempts when no tasks are available
    pub polling_interval_no_tasks: Duration,
    /// Maximum time a worker is allowed to spend processing a single task
    pub task_timeout: Duration,
    /// Maximum time allowed to attempt submitting the result of a completed task
    pub task_submit_timeout: Duration,
    /// Interval to wait before retrying to submit a failed task result
    pub task_resubmit_interval: Duration,
    /// Interval to wait before retrying to fetch a new task if the previous fetch failed
    pub task_fetch_retry_interval: Duration,
    /// The time window over which each worker's utilization is measured
    pub worker_utilization_window: Duration,
    /// Delay before revoking on old certificate after a successful renewal
    pub cert_revocation_delay: Duration,
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
            CERT_REVOCATION_DELAY_AFTER_RENEWAL,
        )
    }
}

/// Builder methods for `WorkerConfig`.
impl WorkerConfig {
    pub fn with_polling_interval_no_tasks(mut self, interval: Duration) -> Self {
        self.polling_interval_no_tasks = interval;
        self
    }

    pub fn with_task_timeout(mut self, timeout: Duration) -> Self {
        self.task_timeout = timeout;
        self
    }

    pub fn with_task_submit_timeout(mut self, timeout: Duration) -> Self {
        self.task_submit_timeout = timeout;
        self
    }

    pub fn with_task_resubmit_interval(mut self, interval: Duration) -> Self {
        self.task_resubmit_interval = interval;
        self
    }
}

/// A worker that processes tasks.
///
/// Workers poll for tasks from a repository, validate domains, issue/renew/delete certificates
/// via ACME, and submit results back to the repository. Each worker tracks metrics
/// and can be gracefully shut down via a cancellation token.
pub struct Worker {
    /// Unique identifier for this worker instance
    pub name: String,
    /// Repository interface for fetching tasks and submitting results
    pub repository: Arc<dyn Repository>,
    /// Domain validator for checking DNS configuration
    pub validator: Arc<dyn ValidatesDomains>,
    /// ACME client for certificate operations
    pub acme_client: Arc<dyn AcmeCertificateClient>,
    /// Configuration settings for timeouts and intervals
    pub config: WorkerConfig,
    /// Metrics collection for observability
    pub metrics: Arc<WorkerMetrics>,
    /// Total seconds since metrics reset
    pub total_sec_since_reset: Arc<AtomicU64>,
    /// Idle seconds since metrics reset
    pub idle_sec_since_reset: Arc<AtomicU64>,
    /// Cancellation token for graceful shutdown
    pub token: CancellationToken,
    /// Task tracker for a graceful shutdown of revocation tasks
    pub task_tracker: TaskTracker,
}

impl Worker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        repository: Arc<dyn Repository>,
        validator: Arc<dyn ValidatesDomains>,
        acme_client: Arc<dyn AcmeCertificateClient>,
        config: WorkerConfig,
        registry: Registry,
        token: CancellationToken,
    ) -> Self {
        Self {
            name,
            repository,
            validator,
            acme_client,
            config,
            metrics: Arc::new(WorkerMetrics::new(registry)),
            total_sec_since_reset: Arc::new(AtomicU64::new(0)),
            idle_sec_since_reset: Arc::new(AtomicU64::new(0)),
            token,
            task_tracker: TaskTracker::new(),
        }
    }

    pub fn schedule_revocation_with_delay(
        &self,
        domain: FQDN,
        certificate: Vec<u8>,
        delay: Duration,
    ) {
        let acme_client = self.acme_client.clone();
        let metrics = self.metrics.clone();
        // Use a child token to allow cancelling revocation tasks independently of the worker
        // Not used at the moment, but could be useful in the future (or as a precaution)
        let token = self.token.child_token();

        self.task_tracker.spawn(async move {
            if delay.is_zero() {
                info!(domain = %domain, "Certificate revocation starts now");
            } else {
                info!(
                    domain = %domain,
                    delay_secs = delay.as_secs(),
                    "Certificate revocation scheduled"
                );
            }

            select! {
                _ = sleep(delay) => {
                    revoke_certificate_with_metrics_update(domain, &certificate, acme_client, &metrics).await;
                }
                _ = token.cancelled() => {
                    warn!(domain = %domain, "Certificate revocation cancelled externally");
                }
            }
        });
    }

    /// Waits for all revocation tasks to complete
    pub async fn shutdown_revocation_tasks(&self) {
        self.task_tracker.close();
        self.task_tracker.wait().await;
    }

    async fn execute_task_with_timeout(&self, task: ScheduledTask) -> TaskResult {
        let start = Instant::now();

        let domain = task.domain;
        let task_id = task.task_id;
        let task_kind = task.kind;
        let certificate = task.certificate;

        info!(
            domain = %domain,
            task_kind = %task.kind,
            "Task execution started"
        );

        let task_result = match time::timeout(self.config.task_timeout, async {
            let domain = domain.clone();

            match task.kind {
                TaskKind::Issue => {
                    issue_task(
                        domain,
                        self.validator.clone(),
                        self.acme_client.clone(),
                        task_id,
                        task_kind,
                    )
                    .await
                }
                TaskKind::Renew => {
                    // - Issue a new certificate.
                    // - If successful, schedule revocation of the old one.
                    //   Revocation is delayed to ensure the new certificate has time to propagate across services (e.g., HTTP gateways).
                    let result = issue_task(
                        domain.clone(),
                        self.validator.clone(),
                        self.acme_client.clone(),
                        task_id,
                        task_kind,
                    )
                    .await;

                    if result.is_success() {
                        if let Some(certificate) = certificate {
                            self.schedule_revocation_with_delay(
                                domain.clone(),
                                certificate,
                                self.config.cert_revocation_delay,
                            );
                        } else {
                            warn!(domain = %domain, "No old certificate provided for renewal task");
                        }
                    }

                    result
                }
                TaskKind::Update => {
                    update_task(domain, self.validator.clone(), task_id, task_kind).await
                }
                TaskKind::Delete => {
                    self.delete_task(domain, task_id, task_kind, certificate)
                        .await
                }
            }
        })
        .await
        {
            Ok(task_result) => task_result.with_duration(start.elapsed()),
            Err(_) => TaskResult::failure(
                domain.clone(),
                TaskFailReason::Timeout {
                    duration_secs: self.config.task_timeout.as_secs(),
                },
                task.task_id,
                task_kind,
            )
            .with_duration(start.elapsed()),
        };

        if task_result.output.is_some() {
            info!(
                domain = %domain,
                task_kind = %task_kind,
                "Task execution succeeded"
            );
        } else if let Some(ref err) = task_result.failure {
            error!(
                domain = %domain,
                task_kind = %task_kind,
                error = ?err,
                "Task execution failed"
            );
        }

        task_result
    }

    /// Executes a delete task:
    /// - validates DNS records for deletion
    /// - schedules immediate certificate revocation
    async fn delete_task(
        &self,
        domain: FQDN,
        task_id: UtcTimestamp,
        task_kind: TaskKind,
        certificate: Option<Vec<u8>>,
    ) -> TaskResult {
        match self.validator.validate_deletion(&domain).await {
            Ok(()) => {
                // Schedule immediate certificate revocation if certificate is present
                if let Some(certificate) = certificate {
                    self.schedule_revocation_with_delay(
                        domain.clone(),
                        certificate,
                        Duration::ZERO,
                    );
                }

                TaskResult::success(domain, TaskOutput::Delete, task_id, task_kind)
            }
            Err(err) => TaskResult::failure(
                domain,
                TaskFailReason::ValidationFailed(err.to_string()),
                task_id,
                task_kind,
            ),
        }
    }
}

// Indicates that worker was stopped externally and it should stop running.
#[derive(Debug, PartialEq, Eq)]
struct WorkerStopped;

impl Worker {
    /// Runs the worker loop, continuously fetching and processing tasks.
    ///
    /// The worker will keep running until the cancellation token is triggered.
    /// Each cycle fetches a task from the repository, processes it, and updates metrics.
    pub async fn run(&self) {
        loop {
            let cycle_start = Instant::now();

            // Check for cancellation before proceeding
            if self.token.is_cancelled() {
                warn!("Worker {} stopped due to cancellation", self.name);
                break;
            }

            // Fetch and process the next pending task
            if self.fetch_and_process_task().await.is_err() {
                break;
            }

            // Publish worker utilization metric if a time window has passed
            let cycle_duration = cycle_start.elapsed().as_secs();
            self.total_sec_since_reset
                .fetch_add(cycle_duration, Ordering::Relaxed);
            self.maybe_update_utilization_metric();
        }

        info!("Worker {} is shutting down ...", self.name);
        self.shutdown_revocation_tasks().await;
        info!("Worker {} shutdown complete", self.name);
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
                    error = ?err,
                    duration_secs = self.config.task_fetch_retry_interval.as_secs(),
                    "Failed to fetch pending task for worker {}, sleeping before retry",
                    self.name
                );
                self.metrics
                    .task_fetches
                    .with_label_values(&[self.name.as_str(), "failure", err.into()])
                    .inc();
                sleep(self.config.task_fetch_retry_interval).await;
                // Update worker idle time for utilization metric
                self.idle_sec_since_reset.fetch_add(
                    self.config.task_fetch_retry_interval.as_secs(),
                    Ordering::Relaxed,
                );
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
                warn!(
                    "Worker {} stopped due to cancellation during task processing",
                    self.name
                );
                return Err(WorkerStopped);
            }

            result = self.execute_task_with_timeout(task.clone()) => result,
        };

        // Submit task result with retries
        self.submit_task_result(&task, task_result.clone()).await?;

        // Calculate task duration
        let task_duration = task_start.elapsed();

        let execution_status = if task_result.is_success() {
            "success"
        } else {
            "failure"
        };

        let execution_failure = task_result
            .failure
            .as_ref()
            .map(|err| err.into())
            .unwrap_or("");

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
                warn!(
                    "Worker {} stopped due to cancellation during idle",
                    self.name
                );
                return Err(WorkerStopped);
            }

            _ = sleep(self.config.polling_interval_no_tasks) => {
                // Update worker idle time for utilization metric
                self.idle_sec_since_reset.fetch_add(
                    self.config.polling_interval_no_tasks.as_secs(),
                    Ordering::Relaxed,
                );
            }
        }

        Ok(())
    }

    /// Updates the worker utilization metric if the window has elapsed
    fn maybe_update_utilization_metric(&self) {
        let total = self.total_sec_since_reset.load(Ordering::Relaxed);

        if total < self.config.worker_utilization_window.as_secs() {
            return;
        }

        // Take values and reset
        let idle = self.idle_sec_since_reset.swap(0, Ordering::Relaxed) as f64;
        let total = self.total_sec_since_reset.swap(0, Ordering::Relaxed) as f64;
        if total == 0.0 {
            return;
        }
        let active = total - idle;

        let utilization = (active * 1000.0 / total).round() / 10.0;

        debug!(
            worker = %self.name,
            active_secs = total - idle,
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

async fn issue_task(
    domain: FQDN,
    validator: Arc<dyn ValidatesDomains>,
    acme_client: Arc<dyn AcmeCertificateClient>,
    task_id: UtcTimestamp,
    task_kind: TaskKind,
) -> TaskResult {
    match validator.validate(&domain).await {
        Ok(canister_id) => match issue_certificate(&domain, canister_id, acme_client).await {
            Ok(output) => TaskResult::success(domain.clone(), output, task_id, task_kind),
            Err(err) => TaskResult::failure(
                domain,
                TaskFailReason::GenericFailure(format_error_chain(&err)),
                task_id,
                task_kind,
            ),
        },
        Err(err) => TaskResult::failure(
            domain,
            TaskFailReason::ValidationFailed(err.to_string()),
            task_id,
            task_kind,
        ),
    }
}

async fn issue_certificate(
    domain: &FQDN,
    canister_id: Principal,
    acme_client: Arc<dyn AcmeCertificateClient>,
) -> anyhow::Result<TaskOutput> {
    let domain_str = domain.to_string();

    // Issue certificate
    let certificate = acme_client
        .issue(vec![domain_str.clone()], None)
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

    // Validate that issued certificate is for the requested domain
    let subject_alt_names = cert
        .subject_alternative_name()?
        .map(|ext| &ext.value.general_names)
        .with_context(|| "Certificate has no Subject Alternative Name")?;

    let cert_domains: Vec<String> = subject_alt_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some(dns.to_string()),
            _ => None,
        })
        .collect();

    if !cert_domains.contains(&domain_str) {
        bail!("Certificate does not contain the requested domain: {domain_str}");
    }

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
    task_kind: TaskKind,
) -> TaskResult {
    match validator.validate(&domain).await {
        Ok(canister_id) => {
            TaskResult::success(domain, TaskOutput::Update(canister_id), task_id, task_kind)
        }
        Err(err) => TaskResult::failure(
            domain,
            TaskFailReason::ValidationFailed(err.to_string()),
            task_id,
            task_kind,
        ),
    }
}

/// Revokes a certificate using the ACME protocol.
async fn revoke_certificate(
    certificate: &[u8],
    acme_client: Arc<dyn AcmeCertificateClient>,
) -> anyhow::Result<()> {
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
        .revoke(&revocation_request)
        .await
        .with_context(|| "certificate revocation failed")?;

    Ok(())
}

async fn revoke_certificate_with_metrics_update(
    domain: FQDN,
    certificate: &[u8],
    acme_client: Arc<dyn AcmeCertificateClient>,
    metrics: &WorkerMetrics,
) {
    match revoke_certificate(certificate, acme_client).await {
        Ok(_) => {
            info!(domain = %domain, "Certificate revocation succeeded");
            metrics
                .certificate_revocations
                .with_label_values(&["success"])
                .inc();
        }
        Err(err) => {
            error!(domain = %domain, error = ?err, "Certificate revocation failed");
            metrics
                .certificate_revocations
                .with_label_values(&["failure"])
                .inc();
        }
    }
}

/// Prometheus metrics for monitoring worker performance and activity.
#[derive(Clone)]
pub struct WorkerMetrics {
    /// Histogram tracking task execution durations
    pub task_executions: HistogramVec,
    /// Counter tracking task submissions (including attempts count)
    pub task_submissions: IntCounterVec,
    /// Counter tracking task fetches
    pub task_fetches: IntCounterVec,
    /// Gauge tracking worker utilization percentage
    pub worker_utilization: GaugeVec,
    /// Counter tracking certificate revocations by status
    pub certificate_revocations: IntCounterVec,
}

impl WorkerMetrics {
    pub fn new(registry: Registry) -> Self {
        Self {
            task_executions: register_histogram_vec_with_registry!(
                "task_execution_duration_seconds",
                "Task execution durations in seconds",
                &["worker_name", "task_kind", "status", "failure"],
                TASK_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),
            task_submissions: register_int_counter_vec_with_registry!(
                "task_submission_with_retries",
                "Total number of task submission (with retries)",
                &[
                    "worker_name",
                    "task_kind",
                    "status",
                    "attempts",
                    "last_failure"
                ],
                registry
            )
            .unwrap(),
            task_fetches: register_int_counter_vec_with_registry!(
                "task_fetch",
                "Total number of task fetching attempts",
                &["worker_name", "status", "failure"],
                registry
            )
            .unwrap(),
            worker_utilization: register_gauge_vec_with_registry!(
                "worker_utilization_percent",
                "Worker utilization percentage",
                &["worker_name"],
                registry
            )
            .unwrap(),
            certificate_revocations: register_int_counter_vec_with_registry!(
                "certificate_revocation",
                "Total number of certificate revocations by status",
                &["status"],
                registry
            )
            .unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow;
    use async_trait::async_trait;
    use candid::Principal;
    use fqdn::FQDN;
    use ic_bn_lib::tls::acme::{
        client::{AcmeCertificateClient, Cert, Error as InstantAcmeError},
        instant_acme::RevocationRequest,
    };
    use prometheus::Registry;
    use rcgen::{CertificateParams, DnType, KeyPair};
    use std::{str::FromStr, sync::Arc, time::Duration};
    use tokio::{spawn, task, time::sleep};
    use tokio_util::sync::CancellationToken;

    use crate::{
        traits::{
            repository::{MockRepository, RepositoryError},
            validation::{MockValidatesDomains, ValidationError},
        },
        types::{
            task::{
                IssueCertificateOutput, ScheduledTask, TaskFailReason, TaskKind, TaskOutput,
                TaskResult,
            },
            worker::{Worker, WorkerConfig, WorkerStopped},
        },
    };

    // Mock ACME client that simulates certificate issuance and revocation
    struct MockAcmeClient;

    #[async_trait]
    impl AcmeCertificateClient for MockAcmeClient {
        async fn issue(
            &self,
            names: Vec<String>,
            _private_key: Option<Vec<u8>>,
        ) -> Result<Cert, InstantAcmeError> {
            // Simulate some delay to make sure executor switching can happen
            sleep(Duration::from_millis(10)).await;

            // Generate cert + key
            let key_pair = KeyPair::generate().unwrap();

            let mut params = CertificateParams::new(names.clone()).unwrap();
            params
                .distinguished_name
                .push(DnType::CommonName, &names[0]);

            let cert = params.self_signed(&key_pair).unwrap();
            let cert_pem = cert.pem();

            Ok(Cert {
                cert: cert_pem.into_bytes(),
                key: vec![],
            })
        }

        async fn revoke<'a>(
            &self,
            _request: &RevocationRequest<'a>,
        ) -> Result<(), InstantAcmeError> {
            // Simulate some delay to make sure executor switching can happen
            sleep(Duration::from_millis(10)).await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_worker_run() {
        // Arrange
        let mut repository = MockRepository::new();
        repository
            .expect_fetch_next_task()
            .times(5..) // Expect at least 5 calls
            .returning(|| {
                Box::pin(async {
                    Ok(Some(ScheduledTask::new(
                        TaskKind::Issue,
                        FQDN::from_str("example.org").unwrap(),
                        123,
                        None,
                    )))
                })
            });

        repository
            .expect_submit_task_result()
            .times(5..) // Should be called for each task that gets executed
            .returning(|_| Box::pin(async { Ok(()) }));

        let mut validator = MockValidatesDomains::new();
        validator.expect_validate().returning(|_| {
            Box::pin(async { Ok(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap()) })
        });

        // Create worker with short polling interval to speed up the test
        let config =
            WorkerConfig::default().with_polling_interval_no_tasks(Duration::from_millis(10));

        let token = CancellationToken::new();

        let worker = Worker::new(
            "test_worker".to_string(),
            Arc::new(repository),
            Arc::new(validator),
            Arc::new(MockAcmeClient),
            config,
            Registry::new(),
            token.clone(),
        );

        // Act: spawn worker in a separate task
        let worker_handle = task::spawn(async move {
            worker.run().await;
        });

        // Let the worker run for a short time to make multiple fetch and submit calls
        sleep(Duration::from_millis(80)).await;

        // Cancel the worker
        token.cancel();

        // Wait for the worker to finish
        worker_handle.await.unwrap();

        // Assert: mocks are verified automatically
    }

    #[tokio::test]
    async fn test_execute_task_success() {
        // Arrange
        let repository = MockRepository::new();
        let mut validator = MockValidatesDomains::new();
        validator.expect_validate().returning(|_| {
            Box::pin(async { Ok(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap()) })
        });
        validator
            .expect_validate_deletion()
            .returning(|_| Box::pin(async { Ok(()) }));

        let worker = Worker::new(
            "test_worker".to_string(),
            Arc::new(repository),
            Arc::new(validator),
            Arc::new(MockAcmeClient),
            WorkerConfig::default(),
            Registry::new(),
            CancellationToken::new(),
        );

        let mut certificate = None;

        // Test all task kinds
        for task_kind in [
            TaskKind::Issue,
            TaskKind::Renew,
            TaskKind::Update,
            TaskKind::Delete,
        ] {
            let task = ScheduledTask::new(
                task_kind,
                FQDN::from_str("example.org").unwrap(),
                123,
                certificate.clone(),
            );

            // Act
            let result = worker.execute_task_with_timeout(task.clone()).await;

            // For Issue and Renew tasks, capture the issued certificate to pass it to Delete task
            if task_kind == TaskKind::Issue || task_kind == TaskKind::Renew {
                certificate = match result.clone().output.unwrap() {
                    TaskOutput::Issue(output) => Some(output.certificate),
                    _ => panic!("Expected certificate"),
                };
            }

            // Assert
            assert!(result.is_success());
            assert_eq!(result.domain, task.domain);
            assert_eq!(result.task_id, task.task_id);
            assert_eq!(result.task_kind, task.kind);
            assert!(result.duration > Duration::ZERO);
            assert!(result.output.is_some());
            assert!(result.failure.is_none());
        }
    }

    #[tokio::test]
    async fn test_execute_task_with_validation_failure() {
        // Arrange
        let repository = MockRepository::new();
        let mut validator = MockValidatesDomains::new();
        validator.expect_validate().returning(|_| {
            Box::pin(async {
                Err(ValidationError::UnexpectedError(anyhow::anyhow!(
                    "Domain validation failed"
                )))
            })
        });

        let worker = Worker::new(
            "test_worker".to_string(),
            Arc::new(repository),
            Arc::new(validator),
            Arc::new(MockAcmeClient),
            WorkerConfig::default(),
            Registry::new(),
            CancellationToken::new(),
        );

        let task = ScheduledTask::new(
            TaskKind::Issue,
            FQDN::from_str("example.org").unwrap(),
            123,
            None,
        );

        // Act
        let result = worker.execute_task_with_timeout(task.clone()).await;

        // Assert
        assert!(!result.is_success());
        assert_eq!(result.domain, task.domain);
        assert_eq!(result.task_id, task.task_id);
        assert_eq!(result.task_kind, task.kind);
        assert!(result.duration > Duration::ZERO);
        assert!(result.output.is_none());
        assert_eq!(
            result.failure.unwrap(),
            TaskFailReason::ValidationFailed("Domain validation failed".to_string())
        );
    }

    #[tokio::test]
    async fn test_execute_task_with_timeout() {
        // Arrange
        let repository = MockRepository::new();
        let mut validator = MockValidatesDomains::new();
        validator.expect_validate().returning(|_| {
            Box::pin(async {
                // Slow validation causing task timeout
                sleep(Duration::from_millis(100)).await;
                Ok(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
            })
        });

        let worker = Worker::new(
            "test_worker".to_string(),
            Arc::new(repository),
            Arc::new(validator),
            Arc::new(MockAcmeClient),
            WorkerConfig::default().with_task_timeout(Duration::from_millis(10)), // Set very short timeout
            Registry::new(),
            CancellationToken::new(),
        );

        let task = ScheduledTask::new(
            TaskKind::Issue,
            FQDN::from_str("example.org").unwrap(),
            123,
            None,
        );

        // Act
        let result = worker.execute_task_with_timeout(task.clone()).await;

        // Assert
        assert!(!result.is_success());
        assert_eq!(result.domain, task.domain);
        assert_eq!(result.task_id, task.task_id);
        assert_eq!(result.task_kind, task.kind);
        assert!(result.duration > Duration::ZERO);
        assert!(result.output.is_none());
        assert_eq!(
            result.failure.unwrap(),
            TaskFailReason::Timeout { duration_secs: 0 }
        );
    }

    #[tokio::test]
    async fn test_submit_task_result_success() {
        // Arrange
        let mut repository = MockRepository::new();
        repository
            .expect_submit_task_result()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let registry = Registry::new();
        let worker = Worker::new(
            "test_worker".to_string(),
            Arc::new(repository),
            Arc::new(MockValidatesDomains::new()),
            Arc::new(MockAcmeClient),
            WorkerConfig::default(),
            registry.clone(),
            CancellationToken::new(),
        );

        let task = ScheduledTask::new(
            TaskKind::Issue,
            FQDN::from_str("example.org").unwrap(),
            123,
            None,
        );

        let task_result = TaskResult::success(
            task.domain.clone(),
            TaskOutput::Issue(IssueCertificateOutput::new(
                Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap(),
                vec![],
                vec![],
                123,
                456,
            )),
            task.task_id,
            task.kind,
        );

        // Act
        let result = worker.submit_task_result(&task, task_result).await;

        // Assert
        assert!(result.is_ok());
        let metric_families = registry.gather();
        let submission_metric = metric_families
            .iter()
            .find(|family| family.name() == "task_submission_with_retries")
            .expect("task_submission_with_retries metric should exist");
        let metric = submission_metric
            .get_metric()
            .iter()
            .find(|m| {
                let labels = m.get_label();
                labels
                    .iter()
                    .any(|l| l.name() == "worker_name" && l.value() == "test_worker")
                    && labels
                        .iter()
                        .any(|l| l.name() == "task_kind" && l.value() == "issue")
                    && labels
                        .iter()
                        .any(|l| l.name() == "attempts" && l.value() == "1")
                    && labels
                        .iter()
                        .any(|l| l.name() == "status" && l.value() == "success")
            })
            .expect("no metric found");
        assert_eq!(metric.get_counter().value, Some(1.0));
    }

    #[tokio::test]
    async fn test_submit_task_result_with_retries_eventual_success() {
        // Arrange
        let mut repository = MockRepository::new();
        repository
            .expect_submit_task_result()
            .times(3) // First 2 calls fail, 3rd succeeds
            .returning({
                let mut call_count = 0;
                move |_| {
                    call_count += 1;
                    Box::pin(async move {
                        if call_count < 3 {
                            Err(RepositoryError::InternalError(anyhow::anyhow!(
                                "Unexpected failure"
                            )))
                        } else {
                            Ok(())
                        }
                    })
                }
            });

        let config = WorkerConfig::default()
            .with_task_submit_timeout(Duration::from_secs(10))
            .with_task_resubmit_interval(Duration::from_millis(10));

        let registry = Registry::new();
        let worker = Worker::new(
            "test_worker".to_string(),
            Arc::new(repository),
            Arc::new(MockValidatesDomains::new()),
            Arc::new(MockAcmeClient),
            config,
            registry.clone(),
            CancellationToken::new(),
        );

        let task = ScheduledTask::new(
            TaskKind::Update,
            FQDN::from_str("example.com").unwrap(),
            456,
            None,
        );

        let task_result = TaskResult::failure(
            task.domain.clone(),
            TaskFailReason::ValidationFailed("some error".to_string()),
            task.task_id,
            task.kind,
        );

        // Act
        let result = worker.submit_task_result(&task, task_result).await;

        // Assert
        assert!(result.is_ok());
        let metric_families = registry.gather();
        let submission_metric = metric_families
            .iter()
            .find(|family| family.name() == "task_submission_with_retries")
            .expect("task_submission_with_retries metric should exist");
        let metric = submission_metric
            .get_metric()
            .iter()
            .find(|m| {
                let labels = m.get_label();
                labels
                    .iter()
                    .any(|l| l.name() == "worker_name" && l.value() == "test_worker")
                    && labels
                        .iter()
                        .any(|l| l.name() == "task_kind" && l.value() == "update")
                    && labels
                        .iter()
                        .any(|l| l.name() == "attempts" && l.value() == "3")
                    && labels
                        .iter()
                        .any(|l| l.name() == "status" && l.value() == "success")
            })
            .expect("no metric found");
        assert_eq!(metric.get_counter().value, Some(1.0));
    }

    #[tokio::test]
    async fn test_submit_task_result_timeout_after_retries() {
        // Arrange
        let mut repository = MockRepository::new();
        repository
            .expect_submit_task_result()
            .times(5..) // Expect multiple calls until timeout
            .returning(|_| {
                Box::pin(async {
                    Err(RepositoryError::InternalError(anyhow::anyhow!(
                        "Some persistent failure"
                    )))
                })
            });

        let registry = Registry::new();
        let config = WorkerConfig::default()
            .with_task_submit_timeout(Duration::from_millis(100)) // Some short timeout
            .with_task_resubmit_interval(Duration::from_millis(10));

        let worker = Worker::new(
            "test_worker".to_string(),
            Arc::new(repository),
            Arc::new(MockValidatesDomains::new()),
            Arc::new(MockAcmeClient),
            config,
            registry.clone(),
            CancellationToken::new(),
        );

        let task = ScheduledTask::new(
            TaskKind::Issue,
            FQDN::from_str("example.net").unwrap(),
            123,
            None,
        );

        let task_result = TaskResult::success(
            task.domain.clone(),
            TaskOutput::Issue(IssueCertificateOutput::new(
                Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap(),
                vec![],
                vec![],
                123,
                456,
            )),
            task.task_id,
            task.kind,
        );

        // Act
        let result = worker.submit_task_result(&task, task_result).await;

        // Assert
        assert!(result.is_ok()); // Function should succeed even if all submissions fails
        let metric_families = registry.gather();
        assert!(!metric_families.is_empty());
    }

    #[tokio::test]
    async fn test_submit_task_result_cancellation_during_retry() {
        // Arrange
        let mut repository = MockRepository::new();
        repository.expect_submit_task_result().returning(|_| {
            Box::pin(async {
                // Slow execution that allows cancellation to kick in
                sleep(Duration::from_millis(2000)).await;
                Err(RepositoryError::InternalError(anyhow::anyhow!(
                    "Some unexpected failure"
                )))
            })
        });

        let token = CancellationToken::new();
        let worker = Worker::new(
            "test_worker".to_string(),
            Arc::new(repository),
            Arc::new(MockValidatesDomains::new()),
            Arc::new(MockAcmeClient),
            WorkerConfig::default(),
            Registry::new(),
            token.clone(),
        );

        let task = ScheduledTask::new(
            TaskKind::Delete,
            FQDN::from_str("example.org").unwrap(),
            123,
            Some(vec![]),
        );

        let task_result = TaskResult::success(
            task.domain.clone(),
            TaskOutput::Delete,
            task.task_id,
            task.kind,
        );

        // Act: spawn submission in the background
        let handle = spawn(async move { worker.submit_task_result(&task, task_result).await });

        // Cancel worker after a short delay
        sleep(Duration::from_millis(25)).await;
        token.cancel();

        let result = handle.await.unwrap();

        // Assert:
        assert_eq!(result.unwrap_err(), WorkerStopped);
    }
}
