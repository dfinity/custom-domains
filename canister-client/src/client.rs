use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use base::{
    traits::{
        repository::{Repository, RepositoryError},
        time::{UtcTimestamp, UtcTimestampProvider},
    },
    types::{
        domain::{CustomDomain, DomainEntry, DomainStatus, RegisteredDomain, RegistrationStatus},
        task::{InputTask, ScheduledTask, TaskKind, TaskOutput, TaskResult},
    },
};
use fqdn::FQDN;
use tracing::{info, warn};
use trait_async::trait_async;

/// A client that currently wraps local State.
///
/// TODO: This is a temporary implementation. Once the actual canister is developed,
/// this client will provide a proper implementation for interacting with it via `agent-rs`.
#[derive(Debug)]
pub struct CanisterClient(pub CanisterState);

// The certificate renewal task is initiated this far ahead of the expiration
const CERT_RENEWAL_BEFORE_EXPIRY: Duration = Duration::from_secs(30 * 24 * 60 * 60);

// The task expires (times out) after this time window if its result isn't submitted.
// This allows the task to be rescheduled if a worker fails.
// Submitting results for expired tasks results in a NonExistingTaskSubmitted error.
const TASK_EXPIRATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);

// If no certificate has been issued, the domain entry is removed after this duration.
const UNREGISTERED_DOMAIN_EXPIRATION_TIME: Duration = Duration::from_secs(24 * 60 * 60);

// If a task fails this many times with a recoverable error, it is no longer rescheduled.
// User is expected to resubmit the task.
const MAX_TASK_FAILURES: u32 = 20;

// If a task fails, it will not be rescheduled earlier than this interval.
const MIN_TASK_RETRY_DELAY: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct CanisterState {
    storage: Arc<Mutex<HashMap<FQDN, DomainEntry>>>,
    last_change: AtomicU64,
    time: Arc<dyn UtcTimestampProvider>,
}

impl CanisterState {
    /// Creates a new state with an empty storage and the provided time source.
    pub fn new(time: Arc<dyn UtcTimestampProvider>) -> Self {
        Self {
            storage: Default::default(),
            last_change: AtomicU64::new(time.unix_timestamp()),
            time,
        }
    }
}

#[trait_async]
impl Repository for CanisterState {
    async fn get_domain_status(
        &self,
        domain: &FQDN,
    ) -> Result<Option<DomainStatus>, RepositoryError> {
        let mutex = self.storage.lock()?;

        match mutex.get(domain) {
            Some(entry) => {
                let status = if entry.task.is_none() && entry.certificate.is_some() {
                    RegistrationStatus::Registered
                } else if entry.task.is_some() {
                    RegistrationStatus::Processing
                } else {
                    RegistrationStatus::Failure(
                        entry
                            .last_failure_reason
                            .clone()
                            .map_or("".to_string(), |failure| failure.to_string()),
                    )
                };

                let domain_status = DomainStatus {
                    domain: domain.clone(),
                    canister_id: entry.canister_id,
                    status,
                };

                Ok(Some(domain_status))
            }
            None => Ok(None),
        }
    }

    /// Fetches the next task ready for execution.
    ///
    /// Also performs:
    /// - Reclaims timed-out tasks, making them available for rescheduling.
    /// - Creates renewal tasks for certificates approaching expirations.
    /// - Removes domains without issued certificates that have exceeded certain duration.
    async fn fetch_next_task(&self) -> Result<Option<ScheduledTask>, RepositoryError> {
        let mut mutex = self.storage.lock()?;
        let now = self.time.unix_timestamp();

        // Process all domains:
        // - Reclaim timed-out tasks for rescheduling.
        // - Create renewal tasks for certificates approaching expiration.
        // - Remove domains without certificates that are too old.
        mutex.retain(|domain, entry| {
            // Reclaim tasks that have exceeded the timeout period.
            if let Some(taken_at) = entry.taken_at {
                let expiry_time = taken_at.saturating_add(TASK_EXPIRATION_TIMEOUT.as_secs());
                if now >= expiry_time {
                    warn!(
                        domain = %domain,
                        task = ?entry.task,
                        "Task timed out and is now available for rescheduling"
                    );
                    entry.taken_at = None;
                }
            }

            // Create a renewal task if the certificate is approaching expiration and no task is active.
            if entry.task.is_none() {
                if let Some(not_after) = entry.not_after {
                    if now >= not_after.saturating_sub(CERT_RENEWAL_BEFORE_EXPIRY.as_secs()) {
                        info!(
                            domain = %domain,
                            expiry = not_after,
                            "Scheduling certificate renewal task"
                        );
                        entry.task = Some(TaskKind::Renew);
                    }
                }
            }

            // Remove domains without certificates that have exceeded the retention period,
            // unless a task is currently active.
            if entry.taken_at.is_none() && entry.certificate.is_none() {
                let expiry_time = entry
                    .created_at
                    .saturating_add(UNREGISTERED_DOMAIN_EXPIRATION_TIME.as_secs());
                if now >= expiry_time {
                    self.last_change.store(now, Ordering::Relaxed);
                    return false;
                }
            }
            true // Keep the domain in storage.
        });

        // Select the first available task and mark it as taken.
        // TODO: Consider prioritizing tasks (e.g., failed tasks) or randomizing selection.
        let scheduled_task = mutex.iter_mut().find_map(|(domain, entry)| {
            // Skip if there's no task or it is already taken.
            let task_kind = match &entry.task {
                Some(task) if entry.taken_at.is_none() => task,
                _ => return None,
            };

            // Check if the task can be retried now.
            if let Some(last_fail) = entry.last_fail_time {
                let next_allowed = last_fail.saturating_add(MIN_TASK_RETRY_DELAY.as_secs());
                if now < next_allowed {
                    return None;
                }
            }

            // mark the task as taken
            entry.taken_at = Some(now);

            let certificate = match task_kind {
                TaskKind::Delete => entry.certificate.clone(),
                _ => None,
            };

            Some(ScheduledTask::new(
                *task_kind,
                domain.clone(),
                now,
                certificate,
            ))
        });

        Ok(scheduled_task)
    }

    /// Submits task result, updating the DomainEntry (or removing it) based on the task kind and status.
    async fn submit_task_result(&self, task_result: TaskResult) -> Result<(), RepositoryError> {
        let mut mutex = self.storage.lock()?;
        let now = self.time.unix_timestamp();

        let domain = &task_result.domain;
        let task_id = task_result.task_id;

        let entry = mutex
            .get_mut(domain)
            .ok_or_else(|| RepositoryError::DomainNotFound(domain.clone()))?;

        // Validate task ID matches `taken_at` (checking `task_kind` is optional)
        if entry.taken_at != Some(task_id) {
            return Err(RepositoryError::NonExistingTaskSubmitted(task_id));
        }

        // Handle task result based on the output or failure
        if let Some(output) = task_result.output {
            // Unset fields in case of task success
            entry.task = None;
            entry.taken_at = None;
            entry.last_failure_reason = None;
            entry.failures_count = 0;
            entry.last_fail_time = None;

            match output {
                TaskOutput::Issue(output) => {
                    info!(
                        domain = %domain,
                        not_before = output.not_before,
                        not_after = output.not_after,
                        "Certificate issued"
                    );
                    entry.canister_id = Some(output.canister_id);
                    entry.certificate = Some(output.certificate);
                    entry.private_key = Some(output.private_key);
                    entry.not_before = Some(output.not_before);
                    entry.not_after = Some(output.not_after);
                    // New certificate was issued, we update the last change time
                    self.last_change.store(now, Ordering::Relaxed);
                }
                TaskOutput::Delete => {
                    info!(domain = %domain, "Domain deleted");
                    mutex.remove(domain);
                    // Domain was removed, we update the last change time
                    self.last_change.store(now, Ordering::Relaxed);
                }
                TaskOutput::Update(canister_id) => {
                    info!(domain = %domain, "Domain updated");
                    entry.canister_id = Some(canister_id);
                }
            }
        } else if let Some(failure) = task_result.failure {
            entry.failures_count += 1;
            entry.last_failure_reason = Some(failure);
            entry.taken_at = None;
            entry.last_fail_time = Some(now);
            // delete the task if the retry limit is reached
            if entry.failures_count >= MAX_TASK_FAILURES {
                entry.task = None;
            }
        }

        Ok(())
    }

    /// Attempts to add a new task for a domain while ensuring no concurrent task exists for the same domain.
    async fn try_add_task(&self, task: InputTask) -> Result<(), RepositoryError> {
        let mut mutex = self.storage.lock()?;
        let domain = &task.domain;

        match mutex.get_mut(domain) {
            Some(entry) => {
                // Prevent scheduling concurrent tasks for domain
                if entry.task.is_some() {
                    return Err(RepositoryError::AnotherTaskInProgress(domain.clone()));
                }
                // Prevent explicit certificate re-issuance
                // TODO: maybe useful functionality for the admin?
                if task.kind == TaskKind::Issue && entry.certificate.is_some() {
                    return Err(RepositoryError::CertificateAlreadyIssued(domain.clone()));
                }
                // Require an existing certificate for `Update` task
                if task.kind == TaskKind::Update && entry.certificate.is_none() {
                    return Err(RepositoryError::MissingCertificateForUpdate(domain.clone()));
                }
                // Set the task field
                entry.task = Some(task.kind);
            }
            None => {
                // Only `Issue` task can create new domain entry
                if task.kind != TaskKind::Issue {
                    return Err(RepositoryError::DomainNotFound(domain.clone()));
                }
                // Insert new domain entry
                mutex.insert(
                    domain.clone(),
                    DomainEntry::new(Some(task.kind), self.time.unix_timestamp()),
                );
            }
        }

        Ok(())
    }

    async fn get_last_change_time(&self) -> Result<UtcTimestamp, RepositoryError> {
        Ok(self.last_change.load(Ordering::Relaxed))
    }

    async fn all_registrations(&self) -> Result<Vec<RegisteredDomain>, RepositoryError> {
        let mutex = self.storage.lock()?;

        let registered_domains = mutex
            .iter()
            .filter_map(|(domain, entry)| {
                let (canister_id, certificate, private_key) = match (
                    entry.canister_id.as_ref(),
                    entry.certificate.as_ref(),
                    entry.private_key.as_ref(),
                ) {
                    (Some(canister_id), Some(cert), Some(key)) => (canister_id, cert, key),
                    _ => return None,
                };

                Some(RegisteredDomain::new(
                    domain.clone(),
                    *canister_id,
                    certificate.clone(),
                    private_key.clone(),
                ))
            })
            .collect();

        Ok(registered_domains)
    }

    async fn all_registered_domains(&self) -> Result<Vec<CustomDomain>, RepositoryError> {
        let mutex = self.storage.lock()?;

        let domains = mutex
            .iter()
            .filter_map(
                |(domain, entry)| match (&entry.certificate, entry.canister_id) {
                    (Some(_), Some(canister_id)) => Some(CustomDomain {
                        domain: domain.clone(),
                        canister_id,
                    }),
                    _ => None,
                },
            )
            .collect();

        Ok(domains)
    }
}

#[cfg(test)]
mod tests {
    use base::{
        traits::{
            repository::{Repository, RepositoryError},
            time::UtcTimestamp,
        },
        types::{
            domain::DomainEntry,
            task::{
                InputTask, IssueCertificateOutput, ScheduledTask, TaskFailReason, TaskKind,
                TaskOutput, TaskResult,
            },
            time::MockTime,
        },
    };
    use pretty_assertions::assert_eq;
    use std::{str::FromStr, sync::Arc};

    use candid::Principal;
    use fqdn::FQDN;

    use crate::client::{
        CERT_RENEWAL_BEFORE_EXPIRY, CanisterState, MAX_TASK_FAILURES, MIN_TASK_RETRY_DELAY,
        TASK_EXPIRATION_TIMEOUT, UNREGISTERED_DOMAIN_EXPIRATION_TIME,
    };

    impl CanisterState {
        /// Add domain entry
        pub fn add_entry(&self, domain: &FQDN, entry: DomainEntry) -> Result<(), RepositoryError> {
            let mut mutex = self.storage.lock()?;
            mutex.insert(domain.clone(), entry);
            Ok(())
        }

        /// Get domain entry
        pub fn get_entry(&self, domain: &FQDN) -> Result<Option<DomainEntry>, RepositoryError> {
            let mutex = self.storage.lock()?;
            Ok(mutex.get(domain).cloned())
        }

        /// Set the certificate field in DomainEntry.
        pub fn set_certificate_field(
            &self,
            domain: &FQDN,
            certificate: Vec<u8>,
        ) -> Result<(), RepositoryError> {
            let mut mutex = self.storage.lock()?;
            if let Some(entry) = mutex.get_mut(domain) {
                entry.certificate = Some(certificate);
            }
            Ok(())
        }

        /// Clears the `task` and `taken_at` fields for a DomainEntry.
        pub fn clear_task_field(&self, domain: &FQDN) -> Result<(), RepositoryError> {
            let mut mutex = self.storage.lock()?;
            if let Some(entry) = mutex.get_mut(domain) {
                entry.task = None;
                entry.taken_at = None;
            }
            Ok(())
        }

        /// Removes a domain and its associated entry from the map.
        pub fn remove_domain(&self, domain: &FQDN) -> Result<(), RepositoryError> {
            let mut mutex = self.storage.lock()?;
            mutex.remove(domain);
            Ok(())
        }

        /// Retrieves the domain's entry, if it exists.
        async fn get_domain(&self, domain: &FQDN) -> Result<Option<DomainEntry>, RepositoryError> {
            let mutex = self.storage.lock()?;
            Ok(mutex.get(domain).cloned())
        }

        async fn mark_task_as_taken(
            &self,
            domain: &FQDN,
            taken_at: UtcTimestamp,
        ) -> Result<(), RepositoryError> {
            let mut mutex = self.storage.lock()?;
            let entry = mutex
                .get_mut(domain)
                .ok_or_else(|| RepositoryError::DomainNotFound(domain.clone()))?;
            entry.taken_at = Some(taken_at);
            Ok(())
        }
    }

    fn create_state_with_mock_time(init_time: UtcTimestamp) -> (Arc<MockTime>, CanisterState) {
        let mock_time = Arc::new(MockTime::new(init_time));
        (mock_time.clone(), CanisterState::new(mock_time))
    }

    // Adding the `Issue` task for a new domain succeeds
    #[tokio::test]
    async fn test_try_add_task_succeeds() -> anyhow::Result<()> {
        // Arrange: create a new state repository and an `Issue` task for a domain
        let init_time = 2;
        let (_, state) = create_state_with_mock_time(init_time);
        let domain = FQDN::from_str("example.org")?;
        let task = InputTask::new(TaskKind::Issue, domain.clone());

        // Act: adding the task should succeed
        state.try_add_task(task.clone()).await?;

        // Assert: domain with the task are added to the storage
        let entry = state.get_domain(&domain).await?.expect("domain not found");
        let expected = DomainEntry {
            task: Some(TaskKind::Issue),
            created_at: init_time,
            ..Default::default()
        };
        assert_eq!(entry, expected);

        Ok(())
    }

    #[tokio::test]
    async fn test_try_add_task_fails_when_another_task_in_progress() -> anyhow::Result<()> {
        // Arrange: create a state repository with an `Issue` task for a domain
        let init_time = 2;
        let (_, state) = create_state_with_mock_time(init_time);
        let domain = FQDN::from_str("example.org")?;
        let initial_task = InputTask::new(TaskKind::Issue, domain.clone());
        state.try_add_task(initial_task).await?;

        // Act: attempt to add any other task while there is a task in progress
        let tasks = vec![
            TaskKind::Issue,
            TaskKind::Update,
            TaskKind::Delete,
            TaskKind::Renew,
        ];
        for task_name in tasks {
            let task = InputTask::new(task_name, domain.clone());
            let result = state.try_add_task(task).await;

            // Assert: all calls fail with AnotherTaskInProgress error
            assert!(
                matches!(result, Err(RepositoryError::AnotherTaskInProgress(ref d)) if d == &domain)
            );
        }

        let entry = state.get_domain(&domain).await?.expect("domain not found");
        let expected = DomainEntry {
            task: Some(TaskKind::Issue),
            created_at: init_time,
            ..Default::default()
        };
        assert_eq!(entry, expected);

        Ok(())
    }

    #[tokio::test]
    async fn test_reissue_task_fails() -> anyhow::Result<()> {
        // Arrange: create a state repository with an issued certificate for a domain
        let init_time = 2;
        let (_, state) = create_state_with_mock_time(init_time);
        let domain = FQDN::from_str("example.org")?;
        let entry = DomainEntry {
            certificate: Some(vec![]),
            ..Default::default()
        };
        state.add_entry(&domain, entry)?;

        // Act: attempt to add another `Issue` task
        let task = InputTask::new(TaskKind::Issue, domain.clone());
        let result = state.try_add_task(task).await;

        // Assert: call fails with CertificateAlreadyIssued
        assert!(
            matches!(result, Err(RepositoryError::CertificateAlreadyIssued(ref d)) if d == &domain),
        );
        let entry = state.get_domain(&domain).await?.expect("domain not found");
        let expected = DomainEntry {
            certificate: Some(vec![]),
            ..Default::default()
        };
        assert_eq!(entry, expected);

        Ok(())
    }

    #[tokio::test]
    async fn test_non_issue_tasks_succeed() -> anyhow::Result<()> {
        // Arrange: create a repository with a completed `Issue` task
        let init_time = 2;
        let (_, state) = create_state_with_mock_time(init_time);
        let domain = FQDN::from_str("example.org")?;
        let initial_task = InputTask::new(TaskKind::Issue, domain.clone());
        state.try_add_task(initial_task).await?;
        state.clear_task_field(&domain)?;
        state.set_certificate_field(&domain, vec![])?;

        // Act + Assert: attempt to add Update/Delete tasks and assert entries in storage
        let tasks = vec![TaskKind::Update, TaskKind::Delete, TaskKind::Renew];
        for task_kind in tasks {
            let task = InputTask::new(task_kind, domain.clone());
            state.try_add_task(task).await?;
            let entry = state.get_domain(&domain).await?.expect("domain not found");
            let expected = DomainEntry {
                task: Some(task_kind),
                created_at: init_time,
                certificate: Some(vec![]),
                ..Default::default()
            };
            assert_eq!(entry, expected);
            state.clear_task_field(&domain)?;
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_try_add_task_fails_for_missing_domain() -> anyhow::Result<()> {
        // Arrange: create a repository with no domain entries
        let (_, state) = create_state_with_mock_time(1);
        let domain = FQDN::from_str("example.org")?;

        // Act: attempt to add Update/Delete tasks for non-existent domain
        let tasks = vec![TaskKind::Update, TaskKind::Delete, TaskKind::Renew];
        for task_kind in tasks {
            let task = InputTask::new(task_kind, domain.clone());
            let result = state.try_add_task(task).await;
            // Assert: calls fail with DomainNotFound error
            assert!(matches!(result, Err(RepositoryError::DomainNotFound(ref d)) if d == &domain),);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_issue_tasks_for_different_domains_succeed() -> anyhow::Result<()> {
        // Arrange: create a repository and with several different domains
        let init_time = 2;
        let (_, state) = create_state_with_mock_time(init_time);
        let domains = vec![
            FQDN::from_str("a.com").expect("Invalid FQDN"),
            FQDN::from_str("b.com").expect("Invalid FQDN"),
        ];

        // Act + Assert: add `Issue` tasks for each domain and assert entry is added
        for domain in &domains {
            let task = InputTask::new(TaskKind::Issue, domain.clone());
            state.try_add_task(task).await?;
            let entry = state.get_domain(domain).await?.expect("domain not found");
            let expected = DomainEntry {
                task: Some(TaskKind::Issue),
                created_at: init_time,
                ..Default::default()
            };
            assert_eq!(entry, expected);
        }

        Ok(())
    }

    /// Test scenario:
    /// 1. Setup: creates two domains with pending `Issue` tasks
    /// 2. Fetch all pending tasks and verify they are of kind `Issue`
    /// 3. Task completion:
    ///    - Submit successful execution results for both tasks
    ///    - Verify no immediate renewal tasks are created
    /// 4. Time-based checks:
    ///    - Advances time to just before renewal threshold:
    ///      - Confirm no renewal tasks appear prematurely
    ///    - Advances time to exact renewal threshold:
    ///      - Verify two correct `Renew` tasks are generated
    ///      - Confirm tasks contain expected domains and IDs
    #[tokio::test]
    async fn test_fetch_next_tasks_succeeds() -> anyhow::Result<()> {
        // Arrange: create a repository with different domains containing `Issue` tasks
        let init_time = 2;
        let (mock_time, state) = create_state_with_mock_time(init_time);
        let domain_a = FQDN::from_str("a.com")?;
        let domain_b = FQDN::from_str("b.com")?;
        let domains = [domain_a.clone(), domain_b.clone()];
        // add domains with `Issue` tasks
        for domain in domains.iter() {
            let task = InputTask::new(TaskKind::Issue, domain.clone());
            state.try_add_task(task).await?;
        }

        // Act + Assert: fetch all tasks and assert they are of TaskKind::Issue
        let mut tasks = vec![];
        while let Ok(Some(task)) = state.fetch_next_task().await {
            tasks.push(task);
        }

        tasks.sort_by(|t1, t2| t1.domain.cmp(&t2.domain));

        let expected_tasks: Vec<_> = domains
            .iter()
            .map(|d| ScheduledTask::new(TaskKind::Issue, d.clone(), init_time, None))
            .collect();

        assert_eq!(tasks, expected_tasks);

        // Act: submit execution results for these tasks
        let not_after = init_time + CERT_RENEWAL_BEFORE_EXPIRY.as_secs() + 1;
        let canister_id = Principal::from_text("aaaaa-aa")?;
        let output = TaskOutput::Issue(IssueCertificateOutput::new(
            canister_id,
            vec![],
            vec![],
            1,
            not_after,
        ));
        let result_a = TaskResult::success(domain_a, output.clone(), init_time);
        let result_b = TaskResult::success(domain_b, output, init_time);
        state.submit_task_result(result_a).await?;
        state.submit_task_result(result_b).await?;
        // check no renewal tasks appeared immediately after submission
        assert!(state.fetch_next_task().await.is_ok_and(|x| x.is_none()));
        // set current time on the edge of the renewal time
        let new_time = not_after.saturating_sub(CERT_RENEWAL_BEFORE_EXPIRY.as_secs()) - 1;
        mock_time.set_time(new_time);
        // assert still no renewal tasks appeared
        assert!(state.fetch_next_task().await.is_ok_and(|x| x.is_none()));
        // finally set current time to expiry, this will trigger creation of renewal tasks
        let new_time = not_after.saturating_sub(CERT_RENEWAL_BEFORE_EXPIRY.as_secs());
        mock_time.set_time(new_time);

        // collect all pending tasks
        tasks.clear();
        while let Ok(Some(task)) = state.fetch_next_task().await {
            tasks.push(task);
        }

        tasks.sort_by(|t1, t2| t1.domain.cmp(&t2.domain));

        let expected_tasks: Vec<_> = domains
            .iter()
            .map(|d| ScheduledTask::new(TaskKind::Renew, d.clone(), new_time, None))
            .collect();

        assert_eq!(tasks, expected_tasks);

        Ok(())
    }

    #[tokio::test]
    async fn test_expired_unregistered_domains_are_removed() -> anyhow::Result<()> {
        // Arrange: create a repository with a failed `Issue` task
        let init_time = 2;
        let (mock_time, state) = create_state_with_mock_time(init_time);
        let domain = FQDN::from_str("example.org")?;
        let entry = DomainEntry {
            task: None,
            created_at: init_time,
            last_failure_reason: Some(TaskFailReason::ValidationFailed("".to_string())),
            ..Default::default()
        };
        state.add_entry(&domain, entry)?;

        // set current time on the edge of the expiry, assert the domain is still present
        let new_time = UNREGISTERED_DOMAIN_EXPIRATION_TIME.as_secs();
        mock_time.set_time(new_time);
        // this call is needed to remove all unregistered domains (if any)
        assert!(state.fetch_next_task().await?.is_none());
        let entry = state.get_domain(&domain).await?.expect("domain not found");
        let expected = DomainEntry {
            created_at: init_time,
            last_failure_reason: Some(TaskFailReason::ValidationFailed("".to_string())),
            ..Default::default()
        };
        assert_eq!(entry, expected);

        // advance time to expiration, assert domain is now removed
        let expiration_time = UNREGISTERED_DOMAIN_EXPIRATION_TIME.as_secs() + init_time;
        mock_time.set_time(expiration_time);
        // this call is needed to remove all unregistered domains (if any)
        assert!(state.fetch_next_task().await?.is_none());
        let entry = state.get_domain(&domain).await?;
        assert!(entry.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_submit_task_result_succeeds() -> anyhow::Result<()> {
        // Arrange: create a new repository with a domain containing an `Issue` task
        let init_time = 2;
        let (_, state) = create_state_with_mock_time(init_time);
        let domain = FQDN::from_str("example.org")?;
        let not_before = 3;
        let not_after = 4;
        let task_id = 2;
        let entry = DomainEntry {
            task: Some(TaskKind::Issue),
            taken_at: Some(task_id),
            created_at: init_time,
            ..Default::default()
        };
        state.add_entry(&domain, entry)?;

        // Act: submit executed tasks. Submission is accepted as ID matches expectation and task hasn't expired yet
        let canister_id = Principal::from_text("aaaaa-aa")?;
        let cert = IssueCertificateOutput::new(canister_id, vec![], vec![], not_before, not_after);
        let tasks = [
            TaskKind::Issue,
            TaskKind::Update,
            TaskKind::Renew,
            TaskKind::Delete,
        ];

        for task in tasks {
            let task_output = match task {
                TaskKind::Issue => TaskOutput::Issue(IssueCertificateOutput::new(
                    canister_id,
                    vec![],
                    vec![],
                    not_before,
                    not_after,
                )),
                TaskKind::Update => TaskOutput::Update(canister_id),
                TaskKind::Renew => TaskOutput::Issue(cert.clone()),
                TaskKind::Delete => TaskOutput::Delete,
            };
            let result = TaskResult::success(domain.clone(), task_output, task_id);
            // Submit executed task.
            state.submit_task_result(result).await?;
            // Assert
            let entry = state.get_domain(&domain).await?;
            if task == TaskKind::Delete {
                assert!(entry.is_none())
            } else {
                let expected = DomainEntry {
                    certificate: Some(vec![]),
                    private_key: Some(vec![]),
                    created_at: init_time,
                    canister_id: Some(canister_id),
                    not_before: Some(not_before),
                    not_after: Some(not_after),
                    ..Default::default()
                };
                assert_eq!(entry.unwrap(), expected);
                state.mark_task_as_taken(&domain, init_time).await?;
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_submitting_expired_task_fails() -> anyhow::Result<()> {
        // Arrange: create a new repository with a domain containing an `Issue` task
        let init_time = 1;
        let (mock_time, state) = create_state_with_mock_time(init_time);
        let domain = FQDN::from_str("example.org")?;
        let task = InputTask::new(TaskKind::Issue, domain.clone());
        state.try_add_task(task.clone()).await?;

        // Act: fetch the task, result will not be submitted before task expiry
        let task_to_timeout = state
            .fetch_next_task()
            .await?
            .expect("no pending task found");
        // assert no more pernding tasks exist
        assert!(state.fetch_next_task().await?.is_none());
        // set current time on the edge of the expiry time, assert no pending tasks exist
        let new_time = TASK_EXPIRATION_TIMEOUT.as_secs();
        mock_time.set_time(new_time);
        assert!(state.fetch_next_task().await?.is_none());
        // advance time to task expiration, now the task can be fetched again and submission with an old ID should fail
        let expiration_time = TASK_EXPIRATION_TIMEOUT.as_secs() + init_time;
        mock_time.set_time(expiration_time);
        let task_to_complete = state
            .fetch_next_task()
            .await?
            .expect("no pending task found");
        // attempt to submit result with the expired task ID fails
        let canister_id = Principal::from_text("aaaaa-aa")?;
        let output = TaskOutput::Issue(IssueCertificateOutput::new(
            canister_id,
            vec![],
            vec![],
            1,
            1,
        ));
        let task_result = TaskResult::success(domain.clone(), output, task_to_timeout.id);
        let result = state.submit_task_result(task_result).await;
        // verify the submission fails
        assert!(
            matches!(result, Err(RepositoryError::NonExistingTaskSubmitted(expired)) if expired == init_time)
        );
        // howerver, submission with the current task ID succeeds
        let canister_id = Principal::from_text("aaaaa-aa")?;
        let not_before = 2;
        let not_after = 3;
        let output = TaskOutput::Issue(IssueCertificateOutput::new(
            canister_id,
            vec![],
            vec![],
            not_before,
            not_after,
        ));
        let valid_result = TaskResult::success(domain.clone(), output, task_to_complete.id);
        state.submit_task_result(valid_result).await?;
        let entry = state.get_domain(&domain).await?.expect("domain not found");
        let expected = DomainEntry {
            created_at: init_time,
            canister_id: Some(canister_id),
            certificate: Some(vec![]),
            private_key: Some(vec![]),
            not_after: Some(not_after),
            not_before: Some(not_before),
            ..Default::default()
        };
        assert_eq!(entry, expected);

        Ok(())
    }

    #[tokio::test]
    async fn test_submit_failed_tasks_with_recoverable_errors() -> anyhow::Result<()> {
        // Arrange: create a new repository with a domain containing some task, e.g. `Update`
        let mut time = 2;
        let (mock_time, state) = create_state_with_mock_time(time);
        let domain = FQDN::from_str("example.org")?;
        let created_at = 2;
        let entry = {
            let mut entry = DomainEntry::new(Some(TaskKind::Update), created_at);
            entry.taken_at = Some(time);
            entry
        };
        state.add_entry(&domain, entry)?;

        // Act: submit recoverable errors MAX_TASK_FAILURES - 1 times
        for i in 0..MAX_TASK_FAILURES - 1 {
            let failure = TaskFailReason::GenericFailure(i.to_string());
            let result = TaskResult::failure(domain.clone(), failure.clone(), time);

            state.submit_task_result(result).await?;

            let entry = state.get_domain(&domain).await?.expect("domain not found");
            // assert failure counts increases with each iteration and last_failure_reason matches
            let expected = DomainEntry {
                task: Some(TaskKind::Update), // failed task still exists, as it will be rescheduled
                failures_count: i + 1,
                last_failure_reason: Some(failure),
                last_fail_time: Some(time),
                created_at,
                ..Default::default()
            };
            assert_eq!(entry, expected);

            // Set the time to just before retry can be scheduled
            time += MIN_TASK_RETRY_DELAY.as_secs() - 1;
            mock_time.set_time(time);
            let task = state.fetch_next_task().await?;
            assert!(task.is_none());

            // Advance time to the threshold and fetch scheduled task for retry
            time += 1;
            mock_time.set_time(time);

            let task = state.fetch_next_task().await?.expect("no task found");
            let task_expected = ScheduledTask::new(TaskKind::Update, domain.clone(), time, None);
            assert_eq!(task, task_expected);
        }

        // Sumbitting failed result once again frees up the task, sets task to `None`
        let failure = TaskFailReason::GenericFailure("last_error".to_string());
        let result = TaskResult::failure(domain.clone(), failure.clone(), time);

        state.submit_task_result(result).await?;

        let entry = state.get_domain(&domain).await?.expect("domain not found");
        let expected = DomainEntry {
            task: None, // this field is now set to None
            failures_count: MAX_TASK_FAILURES,
            last_failure_reason: Some(failure),
            last_fail_time: Some(time),
            created_at,
            ..Default::default()
        };
        assert_eq!(entry, expected);

        // Now there is no more task to fetch, it failed completely and is not rescheduled.
        time += MIN_TASK_RETRY_DELAY.as_secs();
        mock_time.set_time(time);

        assert!(state.fetch_next_task().await?.is_none());

        Ok(())
    }
}
