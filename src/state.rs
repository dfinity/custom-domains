use anyhow::anyhow;
use fqdn::FQDN;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};
use tracing::{info, warn};
use trait_async::trait_async;

use crate::{
    repository::{DomainEntry, Repository, RepositoryError},
    task::{InputTask, ScheduledTask, TaskKind, TaskOutput, TaskResult, TaskStatus},
    time::UnixTimestamp,
};

// The certificate renewal task is initiated this far ahead of the expiration
const CERT_RENEWAL_BEFORE_EXPIRY: Duration = Duration::from_secs(3 * 24 * 60 * 60);

// The task expires (times out) after this time window if its result isn't submitted.
// This allows the task to be rescheduled if a worker fails.
// Submitting results for expired tasks results in a NonExistingTaskSubmitted error.
const TASK_EXPIRATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);

pub struct State {
    storage: Arc<Mutex<HashMap<FQDN, DomainEntry>>>,
    time: Arc<dyn UnixTimestamp>,
}

impl State {
    /// Creates a new state with an empty storage and the provided time source.
    pub fn new(time: Arc<dyn UnixTimestamp>) -> Self {
        Self {
            storage: Default::default(),
            time,
        }
    }
}

impl State {
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
}

#[trait_async]
impl Repository for State {
    /// Retrieves a domain's entry, if it exists.
    async fn get_domain(&self, domain: &FQDN) -> Result<Option<DomainEntry>, RepositoryError> {
        let mutex = self.storage.lock()?;
        Ok(mutex.get(domain).cloned())
    }

    /// Fetches the next task ready for execution.
    ///
    /// Also performs:
    /// - Reclaims timed-out tasks (freeing them for rescheduling).
    /// - Creates renewal tasks if necessary.
    async fn fetch_next_task(&self) -> Result<Option<ScheduledTask>, RepositoryError> {
        let mut mutex = self.storage.lock()?;
        let now = self.time.unix_timestamp();

        // Process all domains:
        // - Reschedule expired (timed out) tasks
        // - Create renewal tasks
        mutex.iter_mut().for_each(|(domain, entry)| {
            // Reschedule expired tasks
            if let Some(taken_at) = entry.taken_at {
                let expiry_time = taken_at.saturating_add(TASK_EXPIRATION_TIMEOUT.as_secs());
                if now >= expiry_time {
                    warn!(
                        domain = %domain,
                        task = ?entry.task,
                        "Task timed out, now set available for rescheduling"
                    );
                    entry.taken_at = None;
                }
            }
            // Create renewal task for certificate approaching expiration:
            //  - Check no task for this domain is currently running
            //  - Check current time has reached renewal time
            if entry.task.is_none() {
                if let Some(not_after) = entry.not_after {
                    if now >= not_after.saturating_sub(CERT_RENEWAL_BEFORE_EXPIRY.as_secs()) {
                        info!(
                            domain = %domain,
                            expiry = not_after,
                            "Creating renewal task"
                        );
                        entry.task = Some(TaskKind::Renew);
                    }
                }
            }
        });

        // Return the first available task, marking it as taken
        // TODO: consider prioritizing failed tasks (or random task selection)
        let scheduled_task = mutex
            .iter_mut()
            .find_map(|(domain, entry)| {
                entry.task.and_then(|task_kind| {
                    entry.taken_at.is_none().then(|| {
                        let taken_at = self.time.unix_timestamp();
                        entry.taken_at = Some(taken_at);
                        ScheduledTask::new(task_kind, domain.clone(), taken_at)
                    })
                })
            })
            .map(Some)
            .unwrap_or(None);

        Ok(scheduled_task)
    }

    /// Submits task result, updating the DomainEntry (or removing it) based on the task kind and status.
    async fn submit_task_result(&self, task_result: TaskResult) -> Result<(), RepositoryError> {
        let mut mutex = self.storage.lock()?;
        let domain = &task_result.domain;
        let task_id = task_result.task_id;

        let entry = mutex
            .get_mut(domain)
            .ok_or_else(|| RepositoryError::DomainNotFound(domain.clone()))?;

        // Validate task ID matches the taken_at field
        if entry.taken_at != Some(task_id) {
            return Err(RepositoryError::NonExistingTaskSubmitted(task_id));
        }

        // Handle task result based on output and status
        match task_result.output {
            TaskOutput::Issue(output) => {
                if task_result.status == TaskStatus::Succeeded {
                    info!(
                        domain = %domain,
                        not_before = output.not_before,
                        not_after = output.not_after,
                        "Certificate issued"
                    );
                    entry.certificate = Some(output.certificate);
                    entry.not_before = Some(output.not_before);
                    entry.not_after = Some(output.not_after);
                    entry.task = None;
                    entry.taken_at = None;
                } else {
                    // TODO: implement fail scenario
                    todo!()
                }
            }
            TaskOutput::Delete => {
                if task_result.status == TaskStatus::Succeeded {
                    info!(
                        domain = %domain,
                        "Domain deleted"
                    );
                    mutex.remove(domain);
                } else {
                    // TODO: implement fail scenario
                    todo!()
                }
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
                if task.kind == TaskKind::Issue {
                    return Err(RepositoryError::CertificateAlreadyIssued(domain.clone()));
                }
                // Require existing certificate for Update task
                if task.kind == TaskKind::Update && entry.certificate.is_none() {
                    return Err(RepositoryError::InternalError(anyhow!(
                        "Update domain task requires an existing issued certificate"
                    )));
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
                    DomainEntry::new(task.kind, self.time.unix_timestamp()),
                );
            }
        }

        Ok(())
    }
}

impl<T> From<PoisonError<T>> for RepositoryError {
    fn from(_value: PoisonError<T>) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use fqdn::FQDN;

    use crate::{
        repository::{Repository, RepositoryError},
        state::{CERT_RENEWAL_BEFORE_EXPIRY, State, TASK_EXPIRATION_TIMEOUT},
        task::{
            InputTask, IssueCertificateOutput, ScheduledTask, TaskKind, TaskOutput, TaskResult,
            TaskStatus,
        },
        time::{MockTime, Timestamp},
    };

    fn create_state_with_mock_time(init_time: Timestamp) -> (Arc<MockTime>, State) {
        let mock_time = Arc::new(MockTime::new(init_time));
        (mock_time.clone(), State::new(mock_time))
    }

    // Adding the `Issue` task for a new domain succeeds
    #[tokio::test]
    async fn test_try_add_task_succeeds() -> anyhow::Result<()> {
        // Arrange: create a new state repository and an `Issue` task for a domain
        let (_, state) = create_state_with_mock_time(1);
        let domain = FQDN::from_str("example.org")?;
        let task = InputTask::new(TaskKind::Issue, domain.clone());

        // Act: adding the task should succeed
        state.try_add_task(task.clone()).await?;

        // Assert: domain with the task are added to the storage
        let entry = state.get_domain(&domain).await?.expect("no domain found");
        assert_eq!(entry.task, Some(TaskKind::Issue));

        Ok(())
    }

    #[tokio::test]
    async fn test_try_add_task_fails_when_another_task_in_progress() -> anyhow::Result<()> {
        // Arrange: create a state repository with an `Issue` task for a domain
        let (_, state) = create_state_with_mock_time(1);
        let domain = FQDN::from_str("example.org")?;
        let initial_task = InputTask::new(TaskKind::Issue, domain.clone());
        state.try_add_task(initial_task).await?;

        // Act: attempt to add various tasks while there is a task in progress
        let tasks = vec![TaskKind::Issue, TaskKind::Update, TaskKind::Delete];
        for task_name in tasks {
            let task = InputTask::new(task_name, domain.clone());
            let result = state.try_add_task(task).await;

            // Assert: all calls fail with AnotherTaskInProgress error
            assert!(
                matches!(result, Err(RepositoryError::AnotherTaskInProgress(ref d)) if d == &domain)
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_reissue_task_fails() -> anyhow::Result<()> {
        // Arrange: create a state repository with a completed `Issue` task
        let (_, state) = create_state_with_mock_time(1);
        let domain = FQDN::from_str("example.org")?;
        let task = InputTask::new(TaskKind::Issue, domain.clone());
        state.try_add_task(task.clone()).await?;
        state.clear_task_field(&domain)?; // unset `task` field, making the task completed

        // Act: attempt to add another `Issue` task
        let result = state.try_add_task(task).await;

        // Assert: call fails with CertificateAlreadyIssued
        assert!(
            matches!(result, Err(RepositoryError::CertificateAlreadyIssued(ref d)) if d == &domain),
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_non_issue_tasks_succeed() -> anyhow::Result<()> {
        // Arrange: create a repository with a completed `Issue` task
        let (_, state) = create_state_with_mock_time(1);
        let domain = FQDN::from_str("example.org")?;
        let initial_task = InputTask::new(TaskKind::Issue, domain.clone());
        state.try_add_task(initial_task).await?;
        state.clear_task_field(&domain)?;
        state.set_certificate_field(&domain, vec![])?;

        // Act + Assert: attempt to add Update/Delete tasks and assert entries in storage
        let tasks = vec![TaskKind::Update, TaskKind::Delete];
        for task_kind in tasks {
            let task = InputTask::new(task_kind, domain.clone());
            state.try_add_task(task).await?;
            let entry = state.get_domain(&domain).await?.expect("domain not found");
            assert_eq!(entry.task, Some(task_kind));
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
        let tasks = vec![TaskKind::Update, TaskKind::Delete];
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
        let (_, state) = create_state_with_mock_time(1);
        let domains = vec![
            FQDN::from_str("a.com").expect("Invalid FQDN"),
            FQDN::from_str("b.com").expect("Invalid FQDN"),
        ];

        // Act + Assert: add `Issue` tasks for each domain and assert entry is added
        for domain in &domains {
            let task = InputTask::new(TaskKind::Issue, domain.clone());
            state.try_add_task(task).await?;
            let entry = state.get_domain(domain).await?.expect("domain not found");
            assert_eq!(entry.task, Some(TaskKind::Issue),);
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
        let init_time = 1;
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
            .map(|d| ScheduledTask::new(TaskKind::Issue, d.clone(), 1))
            .collect();

        assert_eq!(tasks, expected_tasks);

        // Act: submit execution results for these tasks
        let cert_expiry = 1_000_000;
        let output = TaskOutput::Issue(IssueCertificateOutput::new(vec![], vec![], 1, cert_expiry));
        let result_a = TaskResult::new(domain_a, TaskStatus::Succeeded, output.clone(), init_time);
        let result_b = TaskResult::new(domain_b, TaskStatus::Succeeded, output, init_time);
        state.submit_task_result(result_a).await?;
        state.submit_task_result(result_b).await?;
        // check no renewal tasks appeared immediately after submission
        assert!(state.fetch_next_task().await.is_ok_and(|x| x.is_none()));
        // set current time on the edge of the renewal time
        let new_time = cert_expiry.saturating_sub(CERT_RENEWAL_BEFORE_EXPIRY.as_secs()) - 1;
        mock_time.set_time(new_time);
        // assert still no renewal tasks appeared
        assert!(state.fetch_next_task().await.is_ok_and(|x| x.is_none()));
        // finally set current time to expiry, this will trigger creation of renewal tasks
        let new_time = cert_expiry.saturating_sub(CERT_RENEWAL_BEFORE_EXPIRY.as_secs());
        mock_time.set_time(new_time);

        // collect all pending tasks
        tasks.clear();
        while let Ok(Some(task)) = state.fetch_next_task().await {
            tasks.push(task);
        }

        tasks.sort_by(|t1, t2| t1.domain.cmp(&t2.domain));

        let expected_tasks: Vec<_> = domains
            .iter()
            .map(|d| ScheduledTask::new(TaskKind::Renew, d.clone(), new_time))
            .collect();

        assert_eq!(tasks, expected_tasks);

        Ok(())
    }

    #[tokio::test]
    async fn test_submit_task_result_succeeds() -> anyhow::Result<()> {
        // Arrange: create a new repository with a domain containing an `Issue` task
        let (mock_time, state) = create_state_with_mock_time(1);
        let domain = FQDN::from_str("example.org")?;
        let task = InputTask::new(TaskKind::Issue, domain.clone());
        state.try_add_task(task.clone()).await?;

        // Act: advance time to just before the expiration threshold - no task rescheduling occurs at this point
        mock_time.set_time(TASK_EXPIRATION_TIMEOUT.as_secs());
        let task = state
            .fetch_next_task()
            .await?
            .expect("no pending task found");

        // Act: submit executed task. Submission is accepted as IDs match expectations and tasks haven't expired yet
        let output = TaskOutput::Issue(IssueCertificateOutput::new(vec![], vec![], 100, 100));
        let result = TaskResult::new(domain, TaskStatus::Succeeded, output, task.id);
        state.submit_task_result(result).await?;

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

        // Act: fetch the task
        let fetched_task_old = state
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
        let fetched_task_new = state
            .fetch_next_task()
            .await?
            .expect("no pending task found");
        // attempt to submit result with the expired task ID fails
        let output = TaskOutput::Issue(IssueCertificateOutput::default());
        let task_result = TaskResult::new(
            domain.clone(),
            TaskStatus::Succeeded,
            output,
            fetched_task_old.id,
        );
        let result = state.submit_task_result(task_result).await;
        // verify the submission fails
        assert!(
            matches!(result, Err(RepositoryError::NonExistingTaskSubmitted(expired)) if expired == init_time)
        );
        // howerver, submission with the current task ID succeeds
        let output = TaskOutput::Issue(IssueCertificateOutput::default());
        let valid_result = TaskResult::new(
            domain.clone(),
            TaskStatus::Succeeded,
            output,
            fetched_task_new.id,
        );
        state.submit_task_result(valid_result).await?;

        Ok(())
    }
}
